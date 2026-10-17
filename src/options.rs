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
}

pub struct Options {
    pub shell: Option<String>,
    pub disable: Vec<i64>,
    pub enable: Vec<String>,
    pub extended_analysis: Option<bool>,
    pub severity: Severity,
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Options;
    use super::parse_code;
    use shellcheck_rs::Severity;

    #[test]
    fn empty_options_are_defaults() {
        let options = Options::parse("").unwrap_or_else(|error| panic!("{error}"));
        assert!(options.shell.is_none());
        assert!(options.disable.is_empty());
        assert!(matches!(options.severity, Severity::StyleC));
    }

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
            ("not json", "options:"),
        ] {
            let error = Options::parse(source).err().unwrap_or_default();
            assert!(error.contains(fragment), "{source}: {error}");
        }
        assert_eq!(parse_code("SC1"), Some(1));
        assert_eq!(parse_code("SC"), None);
    }
}
