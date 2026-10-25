mod integration;
mod options;
mod script;
mod sources;

pub use actionlint_extension_api::exports;
pub use actionlint_extension_api::kjanat;

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

pub const NAME: &str = "shellcheck";
pub const FILENAME: &str = "actionlint.sh";

pub struct Plugin;

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
            "lint.rules.plugins.shellcheck.options."
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
actionlint_extension_api::export_plugin!(Plugin);

fn analyze_script(script: &Script, options: &Options) -> Outcome {
    match script::request(script, options.shell.as_deref()) {
        Ok(Some(prepared)) => analyze_prepared(script, options, &prepared),
        Ok(None) => Outcome {
            diagnostics: Vec::new(),
            error: None,
        },
        Err(error) => Outcome {
            diagnostics: Vec::new(),
            error: Some(error),
        },
    }
}

fn analyze_prepared(script: &Script, options: &Options, prepared: &script::Prepared) -> Outcome {
    let mut excluded: Vec<i64> = prepared
        .data
        .excluded
        .iter()
        .map(|code| i64::from(*code))
        .collect();
    for code in &options.disable {
        if !excluded.contains(code) {
            excluded.push(*code);
        }
    }
    let spec = CheckSpec {
        filename: FILENAME.to_string(),
        script: prepared.data.text.clone(),
        shell_type_override: prepared.data.dialect.as_deref().and_then(parse_shell),
        ignore_rc: true,
        excluded_warnings: excluded,
        optional_checks: options.enable.clone(),
        extended_analysis: options.extended_analysis,
        min_severity: options.severity,
        ..CheckSpec::default()
    };
    let system: Rc<dyn System> = if options.external_sources {
        Rc::new(sources::Files::new(
            script
                .runtime
                .as_ref()
                .filter(|runtime| runtime.directory_known)
                .map(|runtime| runtime.directory.as_str()),
            &options.source_path,
            &sources::roots(),
        ))
    } else {
        Rc::new(NoExternalSources)
    };
    let result = shellcheck_rs::checker::check_script_with(system, &spec);
    map_result(
        script,
        prepared,
        &prepared.data.sanitized,
        &prepared.data.startup,
        &prepared.data.shell,
        result,
    )
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
        let column = script::realign(&lines, comment.start.line, comment.start.column);
        let attached = prepared.comment_position(comment.start.line, column);
        if line == 0 && attached.is_none() {
            if prepared.is_startup(comment.start.line)
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
        let end_line = prepared.original_line(comment.end.line);
        let end_column = script::realign(&lines, comment.end.line, comment.end.column);
        let message = comment
            .comment
            .message
            .strip_suffix('.')
            .unwrap_or(&comment.comment.message);
        let level = comment.comment.severity.as_str();
        let start = attached
            .or_else(|| position(script, line, column, false))
            .unwrap_or(script.start);
        let end = prepared
            .comment_position(comment.end.line, end_column)
            .or_else(|| position(script, end_line, end_column, true))
            .unwrap_or(start);
        let line = if attached.is_some() { start.line } else { line };
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
mod tests;
