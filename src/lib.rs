mod options;
mod script;
mod shell;

wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
});

use std::rc::Rc;

use exports::kjanat::actionlint::analyzer::Descriptor;
use exports::kjanat::actionlint::analyzer::Diagnostic;
use exports::kjanat::actionlint::analyzer::Edit;
use exports::kjanat::actionlint::analyzer::Fact;
use exports::kjanat::actionlint::analyzer::Fix;
use exports::kjanat::actionlint::analyzer::Guest;
use exports::kjanat::actionlint::analyzer::Input;
use exports::kjanat::actionlint::analyzer::Position;
use exports::kjanat::actionlint::analyzer::Script;
use shellcheck_rs::interface::CheckSpec;
use shellcheck_rs::interface::NoExternalSources;
use shellcheck_rs::interface::PositionedComment;
use shellcheck_rs::interface::Replacement;

use options::Options;
use options::parse_shell;

pub const NAME: &str = "shellcheck-rs";
pub const FILENAME: &str = "actionlint.sh";
const EXCLUDED: &[i64] = &[1091, 2194, 2050, 2153, 2154, 2157, 2043];

struct Plugin;

impl Guest for Plugin {
    fn describe() -> Descriptor {
        Descriptor {
            name: NAME.to_string(),
            requires: vec![Fact::Scripts, Fact::Invocations, Fact::Execution],
        }
    }

    fn analyze(input: Input) -> Result<Vec<Diagnostic>, String> {
        let options = Options::parse(&input.options)?;
        let mut findings = Vec::new();
        for script in input.scripts.iter().chain(input.invoked.iter()) {
            findings.extend(analyze_script(script, &options)?);
        }
        Ok(findings)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Plugin);

#[cfg(target_arch = "wasm32")]
fn debug(message: &str) {
    kjanat::actionlint::host::log(message);
}

#[cfg(not(target_arch = "wasm32"))]
fn debug(_: &str) {}

fn shell_of(script: &Script) -> (String, bool) {
    match &script.runtime {
        Some(runtime) if runtime.shell_known => (runtime.shell.clone(), runtime.shell_implicit),
        Some(_) => (String::new(), false),
        None if script.shell.is_empty() => ("bash".to_string(), true),
        None => (script.shell.clone(), false),
    }
}

pub fn analyze_script(script: &Script, options: &Options) -> Result<Vec<Diagnostic>, String> {
    let (name, implicit) = shell_of(script);
    let (inferred, mut setup) = shell::analysis(&name, implicit);
    let (header, _, directive_shell) = script::header(&script.text);
    if inferred.is_empty() && !directive_shell {
        debug(&format!(
            "{}:{}: skip: no supported dialect for shell {name:?}",
            script.start.line, script.start.column
        ));
        return Ok(Vec::new());
    }
    let mut dialect = inferred.clone();
    if directive_shell {
        dialect = script::header_dialect(header);
    } else if let Some(shell) = &options.shell {
        dialect = shell.clone();
    }
    if dialect != inferred {
        setup = String::new();
    }
    let source = script::sanitize_expressions(&script.text);
    let prepared = script::prepare(&source, &setup);
    let mut excluded = EXCLUDED.to_vec();
    excluded.extend(
        options
            .disable
            .iter()
            .filter(|code| !EXCLUDED.contains(code)),
    );
    let spec = CheckSpec {
        filename: FILENAME.to_string(),
        script: prepared.text.clone(),
        shell_type_override: if directive_shell {
            None
        } else {
            parse_shell(&dialect)
        },
        ignore_rc: true,
        excluded_warnings: excluded,
        optional_checks: options.enable.clone(),
        extended_analysis: options.extended_analysis,
        min_severity: options.severity,
        ..CheckSpec::default()
    };
    let result = shellcheck_rs::checker::check_script_with(Rc::new(NoExternalSources), &spec);
    if let Some(error) = &result.dataflow_error {
        debug(&format!(
            "{}:{}: dataflow analysis stopped: {error:?}",
            script.start.line, script.start.column
        ));
    }
    let lines = prepared.lines();
    let mut findings = Vec::new();
    for comment in &result.comments {
        if comment.start.file != FILENAME {
            continue;
        }
        let line = prepared.original_line(comment.start.line);
        if line == 0 {
            if comment.start.line as usize == prepared.startup_line
                && comment.comment.severity.as_str() != "error"
            {
                continue;
            }
            return Err(format!(
                "startup options {setup:?} for shell {name:?}: SC{}: {}",
                comment.comment.code, comment.comment.message
            ));
        }
        let column = script::realign(&lines, comment.start.line, comment.start.column);
        let end_line = prepared.original_line(comment.end.line);
        let end_column = script::realign(&lines, comment.end.line, comment.end.column);
        let message = comment
            .comment
            .message
            .strip_suffix('.')
            .unwrap_or(&comment.comment.message);
        let level = comment.comment.severity.as_str();
        let start = position(script, line, column, false).unwrap_or(script.start);
        let end = position(script, end_line, end_column, true).unwrap_or(start);
        findings.push(Diagnostic {
            rule: String::new(),
            code: format!("SC{}", comment.comment.code),
            severity: level.to_string(),
            message: format!(
                "shellcheck reported issue in this script: SC{}:{level}:{line}:{column}: {message}",
                comment.comment.code
            ),
            path: script.path.clone(),
            start,
            end,
            fixes: fixes(script, &prepared, &lines, &source, comment),
        });
    }
    Ok(findings)
}

fn fixes(
    script: &Script,
    prepared: &script::Prepared,
    lines: &[&str],
    sanitized: &str,
    comment: &PositionedComment,
) -> Vec<Fix> {
    let Some(fix) = &comment.fix else {
        return Vec::new();
    };
    if fix.replacements.is_empty() {
        return Vec::new();
    }
    let original: Vec<&str> = script.text.split('\n').collect();
    let masked: Vec<&str> = sanitized.split('\n').collect();
    let mut edits = Vec::with_capacity(fix.replacements.len());
    for replacement in &fix.replacements {
        let Some(edit) = edit(script, prepared, lines, &original, &masked, replacement) else {
            return Vec::new();
        };
        edits.push(edit);
    }
    edits.sort_by_key(|edit| (edit.start.line, edit.start.column));
    vec![Fix {
        description: comment.comment.message.clone(),
        edits,
    }]
}

fn edit(
    script: &Script,
    prepared: &script::Prepared,
    lines: &[&str],
    original: &[&str],
    masked: &[&str],
    replacement: &Replacement,
) -> Option<Edit> {
    if replacement.start.line != replacement.end.line
        || replacement.string.contains(['\0', '\r', '\n'])
    {
        return None;
    }
    let line = prepared.original_line(replacement.start.line);
    if line == 0 || original.get(line as usize - 1) != masked.get(line as usize - 1) {
        return None;
    }
    let start_column = script::realign(lines, replacement.start.line, replacement.start.column);
    let end_column = script::realign(lines, replacement.end.line, replacement.end.column);
    if start_column > end_column {
        return None;
    }
    let span = script.spans.iter().find(|span| {
        span.line == line
            && span.start != span.end
            && span.document_end.is_none()
            && start_column >= i64::from(span.start)
            && end_column <= i64::from(span.end)
    })?;
    let column = |text_column: i64| -> Option<Position> {
        Some(Position {
            line: span.document.line,
            column: span.document.column + u32::try_from(text_column).ok()? - span.start,
        })
    };
    Some(Edit {
        path: script.path.clone(),
        start: column(start_column)?,
        end: column(end_column)?,
        replacement: replacement.string.clone(),
    })
}

fn position(script: &Script, line: u32, column: i64, exclusive: bool) -> Option<Position> {
    let column = u32::try_from(column).ok()?;
    for span in &script.spans {
        if span.line != line {
            continue;
        }
        let inside = if exclusive {
            column > span.start && column <= span.end
                || span.start == span.end && column == span.start
        } else {
            column >= span.start && column < span.end
        };
        if !inside {
            continue;
        }
        if let Some(document_end) = span.document_end {
            if exclusive && column == span.end {
                return Some(document_end);
            }
            return Some(span.document);
        }
        return Some(Position {
            line: span.document.line,
            column: span.document.column + column - span.start,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::Options;
    use super::analyze_script;
    use super::exports::kjanat::actionlint::analyzer::Position;
    use super::exports::kjanat::actionlint::analyzer::Runtime;
    use super::exports::kjanat::actionlint::analyzer::Script;
    use super::exports::kjanat::actionlint::analyzer::Span;

    fn script(text: &str, line: u32, column: u32, shell: Option<&str>) -> Script {
        let spans = text
            .split('\n')
            .enumerate()
            .map(|(index, content)| Span {
                line: index as u32 + 1,
                start: 1,
                end: content.chars().count() as u32 + 1,
                document: Position {
                    line: line + index as u32,
                    column,
                },
                document_end: None,
            })
            .collect();
        Script {
            job_id: "build".to_string(),
            step_id: String::new(),
            text: text.to_string(),
            shell: shell.unwrap_or("").to_string(),
            start: Position { line, column },
            path: String::new(),
            spans,
            invocation: None,
            runtime: shell.map(|name| Runtime {
                shell: name.to_string(),
                shell_known: !name.is_empty(),
                shell_implicit: false,
                directory: String::new(),
                directory_known: false,
            }),
        }
    }

    fn defaults() -> Options {
        Options::parse("").unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn unquoted_variable_maps_to_the_document() {
        let findings = analyze_script(&script("echo $x", 7, 14, Some("bash")), &defaults())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(findings.len(), 1, "{findings:?}");
        let finding = &findings[0];
        assert_eq!(finding.code, "SC2086");
        assert_eq!(finding.severity, "info");
        assert_eq!(
            finding.message,
            "shellcheck reported issue in this script: SC2086:info:1:6: Double quote to prevent globbing and word splitting"
        );
        assert_eq!((finding.start.line, finding.start.column), (7, 19));
        assert_eq!((finding.end.line, finding.end.column), (7, 21));
        assert_eq!(finding.fixes.len(), 1);
        let edits = &finding.fixes[0].edits;
        assert_eq!(edits.len(), 2);
        assert_eq!(
            (
                edits[0].start.column,
                edits[0].end.column,
                edits[0].replacement.as_str()
            ),
            (19, 19, "\"")
        );
        assert_eq!(
            (
                edits[1].start.column,
                edits[1].end.column,
                edits[1].replacement.as_str()
            ),
            (21, 21, "\"")
        );
    }

    #[test]
    fn multiline_scripts_use_each_line_span() {
        let findings = analyze_script(
            &script("set -x\n\techo $x\n", 8, 11, Some("bash")),
            &defaults(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!((findings[0].start.line, findings[0].start.column), (9, 17));
    }

    #[test]
    fn expressions_do_not_trigger_constant_warnings() {
        let findings = analyze_script(
            &script(
                "if ${{ matrix.flag }}; then echo on; fi",
                3,
                14,
                Some("bash"),
            ),
            &defaults(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn startup_options_apply_without_findings() {
        let script = script("cat missing | grep x", 3, 14, Some("bash"));
        let findings =
            analyze_script(&script, &defaults()).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            findings.iter().all(|finding| finding.start.line == 3),
            "{findings:?}"
        );
    }

    #[test]
    fn unsupported_shells_and_directives() {
        assert!(
            analyze_script(&script("Write-Host $x", 3, 14, Some("pwsh")), &defaults())
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
        assert!(
            analyze_script(&script("echo $x", 3, 14, Some("")), &defaults())
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
        let findings = analyze_script(
            &script("# shellcheck shell=sh\n[[ -n $x ]]", 3, 14, Some("pwsh")),
            &defaults(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            findings.iter().any(|finding| finding.code == "SC3010"),
            "{findings:?}"
        );
    }

    #[test]
    fn options_select_dialect_and_exclusions() {
        let dash = Options::parse(r#"{"shell": "sh"}"#).unwrap_or_else(|error| panic!("{error}"));
        let findings = analyze_script(&script("[[ -n $x ]]", 3, 14, Some("bash")), &dash)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            findings.iter().any(|finding| finding.code == "SC3010"),
            "{findings:?}"
        );
        let quiet =
            Options::parse(r#"{"disable": ["SC2086"]}"#).unwrap_or_else(|error| panic!("{error}"));
        let findings = analyze_script(&script("echo $x", 3, 14, Some("bash")), &quiet)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn declared_shell_is_used_without_runtime_facts() {
        let findings = analyze_script(&script("[[ -n $x ]]", 3, 14, None), &defaults())
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            findings.iter().all(|finding| finding.code != "SC3010"),
            "{findings:?}"
        );
        let mut sh = script("[[ -n $x ]]", 3, 14, None);
        sh.shell = "sh".to_string();
        let findings = analyze_script(&sh, &defaults()).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            findings.iter().any(|finding| finding.code == "SC3010"),
            "{findings:?}"
        );
    }
}
