use serde::{Deserialize, Serialize};

use crate::exports::kjanat::actionlint::tool_integration::{
    Descriptor, Guest, Negotiated, ResourceRequest,
};
use crate::{Plugin, options};

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct Configuration {
    #[serde(skip_serializing_if = "Option::is_none")]
    shell: Option<String>,
    disable: Vec<String>,
    enable: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extended_analysis: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_sources: Option<bool>,
    source_path: Vec<String>,
    #[serde(skip_serializing)]
    rc_file: Option<String>,
}

impl Guest for Plugin {
    fn describe() -> Descriptor {
        Descriptor {
            tool: "shellcheck".to_string(),
            contract: "kjanat:actionlint/shellcheck-config@0.1.0".to_string(),
            configuration_schema: actionlint_extension_api::SHELLCHECK_CONFIGURATION_SCHEMA
                .to_string(),
        }
    }

    fn negotiate(config: String, options: String) -> Result<Negotiated, String> {
        negotiate(&config, &options)
    }
}

fn negotiate(config: &str, overrides: &str) -> Result<Negotiated, String> {
    let config: Configuration =
        serde_json::from_str(config).map_err(|error| format!("configuration: {error}"))?;
    if config.rc_file.is_some() {
        return Err("this engine does not read ShellCheck rc files".to_string());
    }
    let serde_json::Value::Object(mut combined) =
        serde_json::to_value(config).map_err(|error| error.to_string())?
    else {
        return Err("configuration must be an object".to_string());
    };
    if !overrides.trim().is_empty() {
        let overrides: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(overrides).map_err(|error| format!("options: {error}"))?;
        combined.extend(overrides);
    }
    let encoded = serde_json::to_string(&combined).map_err(|error| error.to_string())?;
    let parsed = options::Options::parse(&encoded)?;
    let external = if combined.contains_key("external-sources") {
        parsed.external_sources
    } else {
        !parsed.source_path.is_empty()
    };
    combined.insert("external-sources".to_string(), external.into());
    let options = serde_json::to_string(&combined).map_err(|error| error.to_string())?;
    let mut resources = Vec::new();
    if external {
        resources.push(ResourceRequest::Workspace);
        for path in parsed.source_path {
            if path != "SCRIPTDIR" && !path.starts_with("SCRIPTDIR/") {
                resources.push(ResourceRequest::Directory(path));
            }
        }
    }
    Ok(Negotiated { options, resources })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_declines_native_only_configuration() {
        for config in [
            r#"{"rc-file":".shellcheckrc"}"#,
            r#"{"disable":["all"]}"#,
            r#"{"disable":["SC2000-SC3000"]}"#,
            r#"{"enable":["not-a-real-check"]}"#,
        ] {
            assert!(negotiate(config, "").is_err(), "{config}");
        }
    }

    #[test]
    fn negotiation_requests_only_enabled_sources() {
        let result = negotiate(r#"{"source-path":["/repo/lib","SCRIPTDIR/lib"]}"#, "")
            .expect("source configuration");
        assert_eq!(result.resources.len(), 2);
        assert!(matches!(result.resources[0], ResourceRequest::Workspace));
        assert!(
            matches!(&result.resources[1], ResourceRequest::Directory(path) if path == "/repo/lib")
        );
        assert!(
            options::Options::parse(&result.options)
                .expect("options")
                .external_sources
        );
        for config in [
            "{}",
            r#"{"external-sources":false,"source-path":["/repo/lib"]}"#,
        ] {
            let result = negotiate(config, "").expect("configuration");
            assert!(result.resources.is_empty());
            assert!(
                !options::Options::parse(&result.options)
                    .expect("options")
                    .external_sources
            );
        }
        assert_eq!(
            negotiate(r#"{"external-sources":true}"#, "")
                .expect("sources")
                .resources
                .len(),
            1
        );
    }

    #[test]
    fn explicit_options_override_configuration_and_recompute_grants() {
        let result = negotiate(
            r#"{"disable":["SC2086"],"source-path":["/old"]}"#,
            r#"{"disable":["SC2034"],"source-path":["/new"]}"#,
        )
        .expect("overrides");
        let parsed = options::Options::parse(&result.options).expect("options");
        assert_eq!(parsed.disable, [2034]);
        assert_eq!(parsed.source_path, ["/new"]);
        assert!(matches!(&result.resources[1], ResourceRequest::Directory(path) if path == "/new"));
        let denied = negotiate(
            r#"{"source-path":["/old"]}"#,
            r#"{"external-sources":false}"#,
        )
        .expect("disabled sources");
        assert!(denied.resources.is_empty());
        assert!(negotiate("{}", r#"{"typo":true}"#).is_err());
    }
}
