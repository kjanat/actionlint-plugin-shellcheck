use super::*;
use exports::kjanat::actionlint::analyzer::{SourceReference, Span};
use kjanat::actionlint::prepared_scripts::{Line, Prepared};

fn script(text: &str) -> Script {
    Script {
        reference: SourceReference {
            document: "workflow.yml".into(),
            revision: "revision-from-host".into(),
            node: "run-node".into(),
            address: "jobs.build.steps[0].run".into(),
        },
        job_id: "build".into(),
        step_id: String::new(),
        text: text.into(),
        shell: "bash".into(),
        start: Position {
            line: 7,
            column: 14,
        },
        path: "workflow.yml".into(),
        spans: vec![Span {
            line: 1,
            start: 1,
            end: u32::try_from(text.chars().count()).expect("fixture length") + 1,
            document: Position {
                line: 7,
                column: 14,
            },
            document_end: None,
        }],
        occurrence: Some("a".repeat(64)),
        runtime: None,
    }
}

fn prepared() -> script::Prepared {
    script::Prepared {
        data: Prepared {
            text: "# shellcheck disable=SC2034\nset -e\necho $x\n".into(),
            sanitized: "echo $x".into(),
            dialect: Some("bash".into()),
            shell: "bash".into(),
            startup: "set -e".into(),
            lines: vec![
                Line::Comment(kjanat::actionlint::source_annotations::Position {
                    line: 6,
                    column: 9,
                }),
                Line::Startup,
                Line::Script(1),
            ],
            excluded: vec![2154],
        },
    }
}

#[test]
fn host_preparation_maps_actual_engine_findings_and_fixes() {
    let source = script("echo $x");
    let outcome = analyze_prepared(&source, &Options::parse("").expect("options"), &prepared());
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert_eq!(outcome.diagnostics.len(), 1);
    let finding = &outcome.diagnostics[0];
    assert_eq!(finding.code, "SC2086");
    assert_eq!((finding.start.line, finding.start.column), (7, 19));
    assert_eq!((finding.end.line, finding.end.column), (7, 21));
    assert_eq!(
        finding.reference.as_ref().expect("reference").node,
        "run-node"
    );
    assert_eq!(finding.fixes[0].revisions[0].digest, "revision-from-host");
    assert_eq!(finding.fixes[0].edits.len(), 2);
    for (edit, column) in finding.fixes[0].edits.iter().zip([19, 21]) {
        assert_eq!(edit.path, "workflow.yml");
        assert_eq!((edit.start.line, edit.start.column), (7, column));
        assert_eq!(edit.replacement, "\"");
    }
}

#[test]
fn generated_lines_and_comments_keep_distinct_source_locations() {
    let prepared = prepared();
    assert_eq!(prepared.original_line(1), 0);
    assert!(prepared.is_startup(2));
    assert_eq!(prepared.original_line(3), 1);
    assert_eq!(prepared.original_line(4), 2);
    let comment = prepared.comment_position(1, 3).expect("comment");
    assert_eq!((comment.line, comment.column), (6, 11));
    assert!(prepared.comment_position(2, 1).is_none());
    assert_eq!(script::realign(&["\techo $x"], 1, 14), 7);
}

#[test]
fn masked_lines_never_receive_engine_fixes() {
    let source = script("echo ${{x}}");
    let outcome = analyze_prepared(&source, &Options::parse("").expect("options"), &prepared());
    assert!(outcome.error.is_none());
    assert!(!outcome.diagnostics.is_empty());
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|finding| finding.fixes.is_empty())
    );
}

#[test]
fn incomplete_engine_result_keeps_findings() {
    let source = script("echo $x");
    let prepared = prepared();
    let mut result = shellcheck_rs::checker::check_script(&CheckSpec {
        filename: FILENAME.into(),
        script: prepared.data.text.clone(),
        shell_type_override: Some(shellcheck_rs::Shell::Bash),
        ..CheckSpec::default()
    });
    result.dataflow_error = Some(shellcheck_rs::cfg::InternalError("Missing root"));
    let outcome = map_result(
        &source,
        &prepared,
        &prepared.data.sanitized,
        &prepared.data.startup,
        &prepared.data.shell,
        result,
    );
    assert!(
        outcome
            .error
            .expect("failure")
            .contains("dataflow analysis stopped")
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|finding| finding.code == "SC2086")
    );
}

#[test]
fn missing_host_preparation_is_an_explicit_failure() {
    let outcome = analyze_script(&script("echo $x"), &Options::parse("").expect("options"));
    assert!(outcome.diagnostics.is_empty());
    assert!(outcome.error.expect("failure").contains("prepared-scripts"));
}
