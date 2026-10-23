mod options;
mod script;
mod shell;
mod sources;

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
use exports::kjanat::actionlint::analyzer::Outcome;
use exports::kjanat::actionlint::analyzer::Position;
use exports::kjanat::actionlint::analyzer::Revision;
use exports::kjanat::actionlint::analyzer::Script;
use shellcheck_rs::interface::CheckResult;
use shellcheck_rs::interface::CheckSpec;
use shellcheck_rs::interface::NoExternalSources;
use shellcheck_rs::interface::PositionedComment;
use shellcheck_rs::interface::Replacement;
use shellcheck_rs::interface::System;

use options::Options;
use options::parse_shell;

pub const NAME: &str = "shellcheck-rs";
pub const FILENAME: &str = "actionlint.sh";
const EXCLUDED: &[i64] = &[1091, 2194, 2050, 2153, 2154, 2157, 2043];

struct Plugin;

impl Guest for Plugin {
    fn describe() -> Descriptor {
        descriptor()
    }

    fn analyze(input: Input) -> Outcome {
        let options = match Options::parse(&input.options) {
            Ok(options) => options,
            Err(error) => {
                return Outcome {
                    diagnostics: Vec::new(),
                    error: Some(error),
                };
            }
        };
        combine(
            input
                .scripts
                .into_iter()
                .chain(input.invoked)
                .map(|mut script| {
                    if script.path.is_empty() {
                        script.path.clone_from(&input.path);
                    }
                    analyze_script(&script, &options)
                }),
        )
    }
}

/// Rule metadata shared by the component and its static package declaration.
pub fn descriptor() -> Descriptor {
    Descriptor {
        description: env!("CARGO_PKG_DESCRIPTION").to_string(),
        category: "correctness".to_string(),
        subcategory: "scripts".to_string(),
        maturity: "experimental".to_string(),
        provider: "shellcheck-rs".to_string(),
        recommended: true,
        explanation: concat!(
            "Checks supported shell snippets with shellcheck-rs. ",
            "External sources require read-only host grants; rc files are not read. Fixes require review."
        )
        .to_string(),
        help: concat!(
            "Configure shell, disable, enable, extended-analysis and severity under ",
            "lint.rules.plugins.shellcheck-rs.options."
        )
        .to_string(),
        documentation_url: env!("CARGO_PKG_REPOSITORY").to_string(),
        fix_availability: "unsafe".to_string(),
        options_schema: options::schema().to_string(),
        examples: Vec::new(),
        name: NAME.to_string(),
        requires: vec![Fact::Scripts, Fact::Invocations, Fact::Execution],
    }
}

fn combine(outcomes: impl IntoIterator<Item = Outcome>) -> Outcome {
    let mut diagnostics = Vec::new();
    let mut errors = Vec::new();
    for outcome in outcomes {
        diagnostics.extend(outcome.diagnostics);
        if let Some(error) = outcome.error {
            errors.push(error);
        }
    }
    Outcome {
        diagnostics,
        error: (!errors.is_empty()).then(|| errors.join("\n")),
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

pub fn analyze_script(script: &Script, options: &Options) -> Outcome {
    let (name, implicit) = shell_of(script);
    let (inferred, mut setup) = shell::analysis(&name, implicit);
    let (header, _, directive_shell) = script::header(&script.text);
    if inferred.is_empty() && !directive_shell {
        debug(&format!(
            "{}:{}: skip: no supported dialect for shell {name:?}",
            script.start.line, script.start.column
        ));
        return Outcome {
            diagnostics: Vec::new(),
            error: None,
        };
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
    let system: Rc<dyn System> = match &script.runtime {
        Some(runtime) if options.external_sources && runtime.directory_known => {
            Rc::new(sources::Files::new(
                &runtime.directory,
                &options.source_path,
                &options.source_roots,
            ))
        }
        _ => Rc::new(NoExternalSources),
    };
    let result = shellcheck_rs::checker::check_script_with(system, &spec);
    map_result(script, &prepared, &source, &setup, &name, result)
}

fn map_result(
    script: &Script,
    prepared: &script::Prepared,
    source: &str,
    setup: &str,
    name: &str,
    result: CheckResult,
) -> Outcome {
    let mut errors = Vec::new();
    if let Some(error) = &result.dataflow_error {
        errors.push(format!(
            "{}:{}:{}: dataflow analysis stopped: {error:?}",
            script.path, script.start.line, script.start.column
        ));
    }
    let lines = prepared.lines();
    let mut findings = Vec::new();
    for comment in &result.comments {
        if comment.start.file != FILENAME {
            match sources::diagnostic(comment) {
                Ok(finding) => findings.push(finding),
                Err(error) => errors.push(error),
            }
            continue;
        }
        let line = prepared.original_line(comment.start.line);
        if line == 0 {
            if comment.start.line as usize == prepared.startup_line
                && comment.comment.severity.as_str() != "error"
            {
                continue;
            }
            errors.push(format!(
                "{}:{}:{}: startup options {setup:?} for shell {name:?}: SC{}: {}",
                script.path,
                script.start.line,
                script.start.column,
                comment.comment.code,
                comment.comment.message
            ));
            continue;
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
            reference: Some(script.reference.clone()),
            explanation: String::new(),
            help: String::new(),
            documentation_url: format!(
                "https://www.shellcheck.net/wiki/SC{}",
                comment.comment.code
            ),
            related: Vec::new(),
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
            fixes: fixes(script, prepared, &lines, source, comment),
        });
    }
    Outcome {
        diagnostics: findings,
        error: (!errors.is_empty()).then(|| errors.join("\n")),
    }
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
        applicability: "unsafe".to_string(),
        revisions: if script.reference.revision.is_empty() {
            Vec::new()
        } else {
            vec![Revision {
                path: script.path.clone(),
                digest: script.reference.revision.clone(),
            }]
        },
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
    use super::exports::kjanat::actionlint::analyzer::Position;
    use super::exports::kjanat::actionlint::analyzer::Runtime;
    use super::exports::kjanat::actionlint::analyzer::Script;
    use super::exports::kjanat::actionlint::analyzer::Span;

    fn analyze_script(
        script: &Script,
        options: &Options,
    ) -> Result<Vec<super::Diagnostic>, String> {
        let outcome = super::analyze_script(script, options);
        match outcome.error {
            Some(error) => Err(error),
            None => Ok(outcome.diagnostics),
        }
    }

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
            reference: super::exports::kjanat::actionlint::analyzer::SourceReference {
                document: String::new(),
                revision: String::new(),
                node: String::new(),
                address: String::new(),
            },
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

    fn input(scripts: Vec<Script>, invoked: Vec<Script>) -> super::Input {
        super::Input {
            reference: script("", 1, 1, None).reference,
            path: "workflow.yml".to_string(),
            content: String::new(),
            kind: "workflow".to_string(),
            parse_status: "complete".to_string(),
            available: Vec::new(),
            options: String::new(),
            scripts,
            invoked,
            mappings: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn document_paths_bind_fixes_without_rewriting_invoked_sources() {
        use super::Guest;
        let mut declared = script("echo $x", 7, 14, Some("bash"));
        declared.reference.revision = "workflow-revision".to_string();
        let mut invoked = script("echo $x", 3, 5, Some("bash"));
        invoked.path = "actions/example/action.yml".to_string();
        invoked.reference.revision = "action-revision".to_string();
        let outcome = super::Plugin::analyze(input(vec![declared], vec![invoked]));
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(outcome.diagnostics.len(), 2);
        for (finding, path, revision) in [
            (&outcome.diagnostics[0], "workflow.yml", "workflow-revision"),
            (
                &outcome.diagnostics[1],
                "actions/example/action.yml",
                "action-revision",
            ),
        ] {
            assert_eq!(finding.path, path);
            assert_eq!(finding.fixes[0].revisions[0].path, path);
            assert_eq!(finding.fixes[0].revisions[0].digest, revision);
            assert!(finding.fixes[0].edits.iter().all(|edit| edit.path == path));
        }
    }

    #[test]
    fn partial_engine_and_startup_failures_keep_findings_and_later_scripts() {
        let source = script("echo $x", 7, 14, Some("bash"));
        let prepared = super::script::prepare(&source.text, "set -e");
        let mut result = shellcheck_rs::checker::check_script(&super::CheckSpec {
            filename: super::FILENAME.to_string(),
            script: prepared.text.clone(),
            shell_type_override: Some(shellcheck_rs::Shell::Bash),
            ..super::CheckSpec::default()
        });
        result.dataflow_error = Some(shellcheck_rs::cfg::InternalError("Missing root"));
        let mut startup = result
            .comments
            .iter()
            .find(|comment| comment.comment.code == 2086)
            .expect("native quote finding")
            .clone();
        startup.start.line = i64::try_from(prepared.startup_line).expect("startup line");
        startup.end.line = startup.start.line;
        startup.comment.severity = shellcheck_rs::Severity::ErrorC;
        result.comments.insert(0, startup);
        let partial = super::map_result(&source, &prepared, &source.text, "set -e", "bash", result);
        assert!(
            partial
                .diagnostics
                .iter()
                .any(|finding| finding.code == "SC2086")
        );
        let error = partial.error.as_deref().expect("partial analysis failure");
        assert!(error.contains("dataflow analysis stopped"), "{error}");
        assert!(error.contains("startup options"), "{error}");
        let outcome = super::combine([
            super::analyze_script(&script("echo $before", 2, 14, Some("bash")), &defaults()),
            partial,
            super::analyze_script(&script("echo $after", 12, 14, Some("bash")), &defaults()),
        ]);
        let lines: Vec<_> = outcome
            .diagnostics
            .iter()
            .filter(|finding| finding.code == "SC2086")
            .map(|finding| finding.start.line)
            .collect();
        assert_eq!(lines, [2, 7, 12]);
        assert!(outcome.error.is_some());
    }

    #[test]
    fn invalid_options_return_an_outcome_error() {
        use super::Guest;
        let mut input = input(Vec::new(), Vec::new());
        input.options = r#"{"shel":"bash"}"#.to_string();
        let outcome = super::Plugin::analyze(input);
        assert!(outcome.diagnostics.is_empty());
        assert!(
            outcome
                .error
                .expect("options error")
                .contains("unknown field")
        );
    }

    #[test]
    fn findings_and_fixes_preserve_source_identity() {
        let mut source = script("echo $x", 7, 14, Some("bash"));
        source.path = "workflow.yml".to_string();
        source.reference.document = source.path.clone();
        source.reference.revision = "revision-from-host".to_string();
        source.reference.node = "run-node".to_string();
        source.reference.address = "jobs.build.steps[0].run".to_string();
        let findings =
            analyze_script(&source, &defaults()).unwrap_or_else(|error| panic!("{error}"));
        let reference = findings[0].reference.as_ref().expect("source reference");
        assert_eq!(reference.document, source.path);
        assert_eq!(reference.node, source.reference.node);
        assert_eq!(reference.revision, source.reference.revision);
        assert_eq!(reference.address, source.reference.address);
        let fix = &findings[0].fixes[0];
        assert_eq!(fix.applicability, "unsafe");
        assert_eq!(fix.revisions.len(), 1);
        assert_eq!(fix.revisions[0].path, source.path);
        assert_eq!(fix.revisions[0].digest, source.reference.revision);
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
    fn named_and_all_optional_selectors_activate_the_engine_check() {
        let source = script("var=hello; echo $var", 3, 14, Some("bash"));
        let baseline = super::analyze_script(&source, &defaults());
        assert!(
            baseline
                .diagnostics
                .iter()
                .all(|finding| finding.code != "SC2250")
        );
        for name in ["require-variable-braces", "all"] {
            let options = Options::parse(&serde_json::json!({"enable": [name]}).to_string())
                .expect("valid optional check");
            let outcome = super::analyze_script(&source, &options);
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            assert!(
                outcome
                    .diagnostics
                    .iter()
                    .any(|finding| finding.code == "SC2250"),
                "{name}: {:?}",
                outcome.diagnostics
            );
        }
    }

    #[test]
    fn dialect_option_does_not_reclassify_unknown_or_unsupported_shells() {
        let options = Options::parse(r#"{"shell":"bash"}"#).expect("valid dialect");
        for shell in ["", "pwsh", "python", "bash -c '{0}'"] {
            let outcome = super::analyze_script(&script("echo $x", 3, 14, Some(shell)), &options);
            assert!(
                outcome.diagnostics.is_empty(),
                "shell {shell:?}: {:?}",
                outcome.diagnostics
            );
            assert!(outcome.error.is_none());
        }
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
