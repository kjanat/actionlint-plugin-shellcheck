use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use exports::kjanat::actionlint::analyzer::{Diagnostic, Position};
use shellcheck_rs::interface::{PositionedComment, System, decode_bytes, not_an_input};

use crate::exports;

/// Source access uses only the filesystem directories granted to this invocation.
pub struct Files {
    directory: Option<PathBuf>,
    paths: Vec<String>,
    roots: Vec<SourceRoot>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRoot {
    pub host: String,
    pub guest: String,
}

impl Files {
    pub fn new(directory: Option<&str>, paths: &[String], roots: &[SourceRoot]) -> Self {
        Self {
            directory: directory.map(PathBuf::from),
            paths: paths.to_vec(),
            roots: roots.to_vec(),
        }
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        if self
            .roots
            .iter()
            .any(|root| within(name, &root.guest, false))
        {
            return Some(normalized(Path::new(name)));
        }
        for root in &self.roots {
            let windows = root.host.get(1..2) == Some(":");
            let name = if windows {
                name.replace('\\', "/")
            } else {
                name.to_string()
            };
            let host = root.host.trim_end_matches('/');
            if within(&name, host, windows) {
                return Some(normalized(
                    &Path::new(&root.guest).join(name[host.len()..].trim_start_matches('/')),
                ));
            }
        }
        if Path::new(name).is_absolute() {
            return Some(normalized(Path::new(name)));
        }
        self.directory
            .as_ref()
            .map(|directory| normalized(&directory.join(name)))
    }
}

fn within(name: &str, root: &str, insensitive: bool) -> bool {
    name.get(..root.len()).is_some_and(|prefix| {
        if insensitive {
            prefix.eq_ignore_ascii_case(root)
        } else {
            prefix == root
        }
    }) && (name.len() == root.len() || name[root.len()..].starts_with('/'))
}

fn normalized(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

fn adjusted(name: &str, script: &str) -> PathBuf {
    let directory = Path::new(script).parent().unwrap_or_else(|| Path::new("."));
    match name.strip_prefix("SCRIPTDIR") {
        Some("") => directory.to_path_buf(),
        Some(rest) if rest.starts_with('/') => directory.join(rest.trim_start_matches('/')),
        _ => PathBuf::from(name),
    }
}

impl System for Files {
    fn read_file(&self, external: Option<bool>, file: &str) -> Result<String, String> {
        if external == Some(false) {
            return Err(not_an_input(external, file));
        }
        let path = self
            .path(file)
            .ok_or_else(|| format!("{file}: working directory is unknown for a relative source"))?;
        std::fs::read(path)
            .map(|bytes| decode_bytes(&bytes))
            .map_err(|error| format!("{file}: {error}"))
    }

    fn find_source(
        &self,
        script: &str,
        external: Option<bool>,
        paths: &[String],
        name: &str,
    ) -> String {
        if external == Some(false) {
            return name.to_string();
        }
        let filename = name.trim_start_matches('/');
        let candidates = std::iter::once(adjusted(filename, script)).chain(
            self.paths
                .iter()
                .chain(paths)
                .map(|directory| adjusted(directory, script).join(filename)),
        );
        for candidate in candidates {
            if let Some(candidate) = self.path(&candidate.to_string_lossy())
                && candidate.is_file()
            {
                return candidate.to_string_lossy().into_owned();
            }
        }
        self.path(name).map_or_else(
            || name.to_string(),
            |path| path.to_string_lossy().into_owned(),
        )
    }
}

pub fn diagnostic(comment: &PositionedComment) -> Result<Diagnostic, String> {
    let bytes = std::fs::read(&comment.start.file)
        .map_err(|error| format!("read diagnostic source {}: {error}", comment.start.file))?;
    let content = decode_bytes(&bytes);
    let lines: Vec<_> = content.split('\n').collect();
    let position = |line: i64, column: i64| -> Result<Position, String> {
        Ok(Position {
            line: u32::try_from(line).map_err(|error| error.to_string())?,
            column: u32::try_from(crate::script::realign(&lines, line, column))
                .map_err(|error| error.to_string())?,
        })
    };
    Ok(Diagnostic {
        reference: None,
        explanation: String::new(),
        help: String::new(),
        documentation_url: format!("https://www.shellcheck.net/wiki/SC{}", comment.comment.code),
        related: Vec::new(),
        rule: String::new(),
        code: format!("SC{}", comment.comment.code),
        severity: comment.comment.severity.as_str().to_string(),
        message: comment.comment.message.clone(),
        path: comment.start.file.clone(),
        start: position(comment.start.line, comment.start.column)?,
        end: position(comment.end.line, comment.end.column)?,
        fixes: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Files, SourceRoot};

    #[test]
    fn host_paths_map_only_to_declared_roots() {
        let files = Files::new(
            Some("/workspace/sub"),
            &[],
            &[
                SourceRoot {
                    host: "/repo".into(),
                    guest: "/workspace".into(),
                },
                SourceRoot {
                    host: "C:/shared".into(),
                    guest: "/sources/0".into(),
                },
            ],
        );
        for (input, expected) in [
            ("/repo/lib/../clean.sh", "/workspace/lib/../clean.sh"),
            (r"c:\shared\clean.sh", "/sources/0/clean.sh"),
            ("/workspace/./lib/../clean.sh", "/workspace/lib/../clean.sh"),
            ("../clean.sh", "/workspace/sub/../clean.sh"),
        ] {
            assert_eq!(files.path(input), Some(PathBuf::from(expected)), "{input}");
        }
        assert_eq!(
            files.path("/repo-other/secret"),
            Some(PathBuf::from("/repo-other/secret"))
        );
    }
}
