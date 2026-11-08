use crate::exports::kjanat::actionlint::analyzer::Position;
use crate::exports::kjanat::actionlint::analyzer::Script;
use crate::kjanat::actionlint_script::environments;
use crate::kjanat::actionlint_script::shell_script_inputs;
use rshellcheck_core::ast::Annotation;
use rshellcheck_core::ast::InnerToken;

pub struct Prepared {
    pub data: shell_script_inputs::Input,
}

#[cfg(target_arch = "wasm32")]
pub fn request(script: &Script, dialect: Option<&str>) -> Result<Option<Prepared>, String> {
    let occurrence = script
        .occurrence
        .as_deref()
        .ok_or("script occurrence missing")?;
    let Some(mut data) = shell_script_inputs::for_script(occurrence, None)? else {
        return Ok(None);
    };
    let declared = declared_shell(&data.text);
    if data.dialect.is_none() && declared.is_none() {
        return Ok(None);
    }
    let selected = declared.as_deref().or(dialect);
    if selected.is_some() && selected != data.dialect.as_deref() {
        let Some(rebuilt) = shell_script_inputs::for_script(occurrence, selected)? else {
            return Ok(None);
        };
        data = rebuilt;
    }
    if declared.is_some() {
        data.dialect = None;
    }
    Ok(Some(Prepared { data }))
}

// Parse leading comments with ShellCheck so a broken script body cannot hide
// the shell directive. ShellCheck also handles directive quoting.
pub fn declared_shell(text: &str) -> Option<String> {
    let mut header = text
        .lines()
        .take_while(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    header.push_str("\ntrue\n");
    let parsed = rshellcheck_core::parser::parse_script(crate::FILENAME, &header);
    let mut token = parsed.root.as_ref()?;
    while let InnerToken::T_Annotation {
        annotations,
        token: inner,
    } = &*token.inner
    {
        for annotation in annotations {
            if let Annotation::ShellOverride(name) = annotation {
                return Some(name.clone());
            }
        }
        token = inner;
    }
    None
}

pub fn excluded_codes(script: &Script) -> Result<Vec<i64>, String> {
    #[cfg(target_arch = "wasm32")]
    let facts = environments::for_script(
        script
            .occurrence
            .as_deref()
            .ok_or("script occurrence missing")?,
    )?;
    #[cfg(not(target_arch = "wasm32"))]
    let facts = {
        let _ = script;
        Vec::new()
    };
    Ok(exclusions_for_environment(&facts))
}

fn exclusions_for_environment(facts: &[environments::Environment]) -> Vec<i64> {
    let mut excluded = vec![1091, 2194, 2050, 2157, 2043];
    if facts.is_empty()
        || facts.iter().any(|environment| {
            environment.unknown_names
                || matches!(
                    environment.lookup_comparison,
                    environments::NameComparison::Unknown
                )
                || environment.names.iter().any(|name| !name.case_known)
        })
    {
        excluded.extend([2153, 2154]);
    }
    excluded
}

#[cfg(not(target_arch = "wasm32"))]
pub fn request(_: &Script, _: Option<&str>) -> Result<Option<Prepared>, String> {
    Err("analysis requires the shell-script-inputs host interface".to_string())
}

impl Prepared {
    fn line(&self, line: i64) -> Option<&shell_script_inputs::Line> {
        usize::try_from(line.checked_sub(1)?)
            .ok()
            .and_then(|index| self.data.lines.get(index))
    }

    pub fn is_startup(&self, line: i64) -> bool {
        matches!(self.line(line), Some(shell_script_inputs::Line::Generated))
    }

    pub fn comment_position(&self, line: i64, column: i64) -> Option<Position> {
        let shell_script_inputs::Line::Comment(start) = self.line(line)? else {
            return None;
        };
        Some(Position {
            line: start.line,
            column: start
                .column
                .checked_add(u32::try_from(column).ok()?.checked_sub(1)?)?,
        })
    }

    pub fn original_line(&self, line: i64) -> u32 {
        if usize::try_from(line).ok() == self.data.lines.len().checked_add(1) {
            for source in self.data.lines.iter().rev() {
                if let shell_script_inputs::Line::Source(source) = source {
                    return source.saturating_add(1);
                }
            }
        }
        match self.line(line) {
            Some(shell_script_inputs::Line::Source(source)) => *source,
            _ => 0,
        }
    }

    pub fn lines(&self) -> Vec<&str> {
        self.data.text.split('\n').collect()
    }
}

fn real_column(line: &str, target: i64) -> i64 {
    let mut real: i64 = 0;
    let mut virtual_column: i64 = 0;
    for c in line.chars() {
        if target <= virtual_column {
            return real;
        }
        if c == '\t' {
            virtual_column += 8 - (virtual_column % 8);
        } else {
            virtual_column += 1;
        }
        real += 1;
    }
    if target <= virtual_column {
        return real;
    }
    real + (target - virtual_column)
}

pub fn realign(lines: &[&str], line: i64, column: i64) -> i64 {
    usize::try_from(line - 1)
        .ok()
        .and_then(|index| lines.get(index))
        .map_or(column, |text| real_column(text, column))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_directives_use_the_engine_parser() {
        for (source, expected) in [
            ("# shellcheck shell=sh\necho hi", Some("sh")),
            ("# shellcheck disable=SC2086 shell='ksh'\n(", Some("ksh")),
            (
                "# shellcheck source-path=\"directory with spaces\" shell=bash\n",
                Some("bash"),
            ),
            ("# shellcheck source-path=\"directory shell=bash\"\n", None),
            ("# shellcheck shell=unknown\n", Some("unknown")),
            ("#!/bin/sh\necho hi", None),
            ("# Example: shellcheck shell=bash\n", None),
            ("echo hi\n# shellcheck shell=sh\n", None),
        ] {
            assert_eq!(declared_shell(source).as_deref(), expected, "{source}");
        }
    }

    #[test]
    fn unassigned_checks_depend_on_environment_knowledge() {
        use environments::Environment;
        use environments::EnvironmentScope;
        use environments::NameComparison;
        use environments::OperatingSystem;
        use environments::VariableName;
        let known = || Environment {
            operating_system: OperatingSystem::Linux,
            merge_comparison: NameComparison::Sensitive,
            lookup_comparison: NameComparison::Sensitive,
            unknown_names: false,
            names: vec![VariableName {
                name: "lowercase".into(),
                scope: EnvironmentScope::Step,
                case_known: true,
            }],
        };
        assert_eq!(
            exclusions_for_environment(&[known()]),
            [1091, 2194, 2050, 2157, 2043]
        );
        let expected = [1091, 2194, 2050, 2157, 2043, 2153, 2154];
        assert_eq!(exclusions_for_environment(&[]), expected);
        let mut unresolved = known();
        unresolved.unknown_names = true;
        assert_eq!(exclusions_for_environment(&[known(), unresolved]), expected);
        let mut spelling = known();
        spelling.names[0].case_known = false;
        assert_eq!(exclusions_for_environment(&[spelling]), expected);
        let mut lookup = known();
        lookup.lookup_comparison = NameComparison::Unknown;
        assert_eq!(exclusions_for_environment(&[lookup]), expected);
    }
}
