use serde::Deserialize;
use shellcheck_rs::Severity;
use shellcheck_rs::Shell;

#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
struct Raw {
    shell: Option<String>,
    disable: Vec<String>,
    enable: Vec<String>,
    extended_analysis: Option<bool>,
    severity: Option<String>,
    external_sources: bool,
    source_path: Vec<String>,
}

pub fn schema() -> serde_json::Value {
    let optional_names: Vec<_> = std::iter::once("all")
        .chain(
            shellcheck_rs::optional_checks()
                .iter()
                .map(|check| check.name),
        )
        .collect();
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ShellCheck plugin options",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "shell": {
                "description": "Override an already supported shell's inferred dialect, unless a header directive selects one.",
                "type": "string",
                "enum": ["bash", "sh", "dash", "ksh", "busybox"]
            },
            "disable": {
                "description": "Diagnostic codes to suppress, with optional SC prefix; these are not optional-check names.",
                "examples": [["SC2086", "2154"]],
                "type": "array",
                "items": {"type": "string", "pattern": "^(SC)?[0-9]+$"}
            },
            "enable": {
                "description": "Optional checks to activate by exact name, or all. Numeric diagnostic codes are not accepted.",
                "examples": [["require-variable-braces", "clarify-parse-errors"], ["all"]],
                "type": "array",
                "items": {"type": "string", "enum": optional_names}
            },
            "external-sources": {"type": "boolean", "description": "Follow sources only within read-only filesystem grants supplied by the host."},
            "source-path": {"type": "array", "items": {"type": "string"}},
            "extended-analysis": {"type": "boolean"},
            "severity": {"type": "string", "enum": ["error", "warning", "info", "style"]}
        }
    })
}

pub struct Options {
    pub shell: Option<String>,
    pub disable: Vec<i64>,
    pub enable: Vec<String>,
    pub extended_analysis: Option<bool>,
    pub severity: Severity,
    pub external_sources: bool,
    pub source_path: Vec<String>,
}

pub fn parse_shell(name: &str) -> Option<Shell> {
    match name {
        "bash" => Some(Shell::Bash),
        "sh" => Some(Shell::Sh),
        "dash" => Some(Shell::Dash),
        "ksh" => Some(Shell::Ksh),
        "busybox" => Some(Shell::BusyboxSh),
        _ => None,
    }
}

pub fn parse_code(code: &str) -> Option<i64> {
    let digits = code.strip_prefix("SC").unwrap_or(code);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

impl Options {
    pub fn parse(options: &str) -> Result<Self, String> {
        let raw: Raw = if options.trim().is_empty() {
            Raw::default()
        } else {
            serde_json::from_str(options).map_err(|error| format!("options: {error}"))?
        };
        if let Some(shell) = &raw.shell
            && parse_shell(shell).is_none()
        {
            return Err(format!(
                "options: shell {shell:?} is not one of bash, sh, dash, ksh or busybox"
            ));
        }
        let mut disable = Vec::with_capacity(raw.disable.len());
        for code in &raw.disable {
            disable.push(
                parse_code(code)
                    .ok_or_else(|| format!("options: disable entry {code:?} is not an SC code"))?,
            );
        }
        for name in &raw.enable {
            if name != "all"
                && !shellcheck_rs::optional_checks()
                    .iter()
                    .any(|check| check.name == name)
            {
                return Err(format!(
                    "options: enable entry {name:?} is not a supported optional check name or all"
                ));
            }
        }
        let severity = match raw.severity.as_deref() {
            None | Some("style") => Severity::StyleC,
            Some("info") => Severity::InfoC,
            Some("warning") => Severity::WarningC,
            Some("error") => Severity::ErrorC,
            Some(other) => {
                return Err(format!(
                    "options: severity {other:?} is not one of error, warning, info or style"
                ));
            }
        };
        Ok(Self {
            shell: raw.shell,
            disable,
            enable: raw.enable,
            extended_analysis: raw.extended_analysis,
            severity,
            external_sources: raw.external_sources,
            source_path: raw.source_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Options;
    use super::parse_code;
    use shellcheck_rs::Severity;

    // A plugin installation without an options object must remain usable. The
    // empty-string input takes a separate path from JSON deserialization, so this
    // checks that it neither forces a dialect nor suppresses diagnostics and that
    // the default severity includes style findings rather than silently hiding them.
    #[test]
    fn empty_options_are_defaults() {
        let options = Options::parse("").unwrap_or_else(|error| panic!("{error}"));
        assert!(options.shell.is_none());
        assert!(options.disable.is_empty());
        assert!(options.enable.is_empty());
        assert!(options.extended_analysis.is_none());
        assert!(!options.external_sources);
        assert!(options.source_path.is_empty());
        assert!(matches!(options.severity, Severity::StyleC));
    }

    // Configuration mistakes should fail at the plugin boundary with the offending
    // field identified, rather than silently changing analysis. This exercises
    // conversions and malformed dialect, exclusion, optional-check and severity
    // values, including numeric diagnostic exclusions versus named optional checks.
    #[test]
    fn options_are_validated() {
        let options = Options::parse(r#"{"shell": "dash", "disable": ["SC2086", "2034"], "enable": ["avoid-nullary-conditions"], "extended-analysis": false, "severity": "warning"}"#)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(options.shell.as_deref(), Some("dash"));
        assert_eq!(options.disable, vec![2086, 2034]);
        assert_eq!(options.enable, vec!["avoid-nullary-conditions"]);
        assert_eq!(options.extended_analysis, Some(false));
        assert!(matches!(options.severity, Severity::WarningC));
        for (source, fragment) in [
            (r#"{"shell": "fish"}"#, "shell \"fish\""),
            (r#"{"disable": ["bad"]}"#, "disable entry \"bad\""),
            (r#"{"severity": "loud"}"#, "severity \"loud\""),
            (r#"{"unknown": 1}"#, "unknown field"),
            (r#"{"enable": ["require-variable-brace"]}"#, "enable entry"),
            (r#"{"enable": ["SC2086"]}"#, "enable entry"),
            (r#"{"enable": ["2086"]}"#, "enable entry"),
            ("not json", "options:"),
        ] {
            let error = Options::parse(source).err().unwrap_or_default();
            assert!(error.contains(fragment), "{source}: {error}");
        }
        assert_eq!(parse_code("SC1"), Some(1));
        assert_eq!(parse_code("SC"), None);
    }

    // Editors use the published schema while the guest validates options at
    // runtime; disagreement makes suggested settings unusable. This checks every
    // engine-provided optional-check name in the generated schema and then submits
    // that catalogue to the parser, covering their shared public configuration surface.
    #[test]
    fn schema_and_validation_use_the_engine_catalogue() {
        let schema = super::schema();
        let names: Vec<String> =
            serde_json::from_value(schema["properties"]["enable"]["items"]["enum"].clone())
                .expect("optional-check enum");
        assert_eq!(names.len(), shellcheck_rs::optional_checks().len() + 1);
        assert_eq!(names[0], "all");
        for check in shellcheck_rs::optional_checks() {
            assert!(names.iter().any(|name| name == check.name));
        }
        let options = serde_json::json!({"enable": names}).to_string();
        assert!(Options::parse(&options).is_ok());
        assert!(Options::parse(r#"{"enable":["all"]}"#).is_ok());
    }
}
