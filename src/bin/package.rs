use std::borrow::Cow;
use std::error::Error;
use std::fs;
use std::path::Path;

use actionlint_plugin_shellcheck::exports::kjanat::actionlint::analyzer::Fact;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use wasm_encoder::Component;
use wasm_encoder::CustomSection;
use wasm_encoder::RawSection;
use wasmparser::Encoding;
use wasmparser::Parser;
use wasmparser::Payload;
use wasmparser::Validator;

const SECTION: &str = "actionlint.plugin";
const WIT: &str = include_str!("../../wit/analyzer.wit");
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn metadata() -> Result<Vec<u8>> {
    let rule = actionlint_plugin_shellcheck::descriptor();
    let schema: serde_json::Value = serde_json::from_str(&rule.options_schema)?;
    let requires: Vec<_> = rule
        .requires
        .iter()
        .map(|fact| match fact {
            Fact::Source => "source",
            Fact::Scripts => "scripts",
            Fact::Mappings => "mappings",
            Fact::Invocations => "invocations",
            Fact::Execution => "execution",
            Fact::Dependencies => "dependencies",
        })
        .collect();
    let value = json!({
        "metadata_version": 1,
        "id": rule.name,
        "name": "ShellCheck",
        "description": env!("CARGO_PKG_DESCRIPTION"),
        "license": env!("CARGO_PKG_LICENSE"),
        "repository": env!("CARGO_PKG_REPOSITORY"),
        "plugin_version": env!("CARGO_PKG_VERSION"),
        "transport": "wasm-component",
        "interface": "kjanat:actionlint/analyzer@0.1.0",
        "contract_sha256": digest(WIT.replace("\r\n", "\n").as_bytes()),
        "engine": {"name": "shellcheck-rs", "version": "1.0.0"},
        "languages": ["shell"],
        "capabilities": {"filesystem": true, "network": false, "fixes": true},
        "descriptor": {
            "name": rule.name,
            "description": rule.description,
            "category": rule.category,
            "subcategory": rule.subcategory,
            "maturity": rule.maturity,
            "provider": rule.provider,
            "recommended": rule.recommended,
            "explanation": rule.explanation,
            "help": rule.help,
            "documentation_url": rule.documentation_url,
            "fix_availability": rule.fix_availability,
            "options_schema": schema,
            "requires": requires
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Replace only the outer component's discovery section, preserving nested modules.
fn with_metadata(input: &[u8], metadata: &[u8]) -> Result<Vec<u8>> {
    Validator::new().validate_all(input)?;
    let mut component = Component::new();
    component.section(&CustomSection {
        name: Cow::Borrowed(SECTION),
        data: Cow::Borrowed(metadata),
    });
    let mut depth = 0;
    for payload in Parser::new(0).parse_all(input) {
        let payload = payload?;
        if let Payload::Version { encoding, .. } = payload {
            if depth == 0 && encoding != Encoding::Component {
                return Err("input must be a WebAssembly component".into());
            }
            depth += 1;
        } else if matches!(payload, Payload::End(_)) {
            depth -= 1;
        } else if depth == 1 {
            if let Payload::CustomSection(section) = &payload
                && section.name() == SECTION
            {
                continue;
            }
            if let Some((id, range)) = payload.as_section() {
                let range = usize::try_from(range.start)?..usize::try_from(range.end)?;
                component.section(&RawSection {
                    id,
                    data: &input[range],
                });
            }
        }
    }
    Ok(component.finish())
}

fn package(input: &Path, output: &Path) -> Result<()> {
    let metadata = metadata()?;
    let wasm = with_metadata(&fs::read(input)?, &metadata)?;
    let schema: serde_json::Value =
        serde_json::from_str(&actionlint_plugin_shellcheck::descriptor().options_schema)?;
    let mut schema = serde_json::to_vec_pretty(&schema)?;
    schema.push(b'\n');
    let files = [
        ("plugin.wasm", wasm),
        ("metadata.json", metadata),
        ("schema.json", schema),
        (
            "LICENSE",
            include_str!("../../LICENSE")
                .replace("\r\n", "\n")
                .into_bytes(),
        ),
    ];
    let checksums = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", digest(bytes)))
        .collect::<String>();
    fs::create_dir_all(output)?;
    for (name, bytes) in files {
        fs::write(output.join(name), bytes)?;
    }
    fs::write(output.join("SHA256SUMS"), checksums)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [input, output] = args.as_slice() else {
        return Err("usage: package <component.wasm> <output-directory>".into());
    };
    package(Path::new(input), Path::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::Module;
    use wasm_encoder::ModuleSection;

    // Repackaging must replace only this component's discovery metadata, without
    // damaging embedded modules or their identically named sections. This builds
    // a nested component, packages it twice and validates the result, checking both
    // deterministic bytes and the survival of unrelated and nested section contents.
    #[test]
    fn packaging_is_idempotent_and_keeps_nested_custom_sections() -> Result<()> {
        let mut module = Module::new();
        module.section(&CustomSection {
            name: Cow::Borrowed(SECTION),
            data: Cow::Borrowed(b"nested"),
        });
        let mut component = Component::new();
        component.section(&CustomSection {
            name: Cow::Borrowed("other"),
            data: Cow::Borrowed(b"preserved"),
        });
        component.section(&ModuleSection(&module));
        let metadata = metadata()?;
        let packaged = with_metadata(&component.finish(), &metadata)?;
        assert_eq!(packaged, with_metadata(&packaged, &metadata)?);
        Validator::new().validate_all(&packaged)?;
        let mut sections = Vec::new();
        for payload in Parser::new(0).parse_all(&packaged) {
            if let Payload::CustomSection(section) = payload? {
                sections.push((section.name().to_string(), section.data().to_vec()));
            }
        }
        assert_eq!(
            sections,
            vec![
                (SECTION.to_string(), metadata),
                ("other".to_string(), b"preserved".to_vec()),
                (SECTION.to_string(), b"nested".to_vec())
            ]
        );
        Ok(())
    }

    // The publication path promises a component, so wrapping a core module or
    // malformed component with plausible metadata would create an unusable release.
    // These binary inputs exercise the packager's format validation before it
    // produces output, independently of the happy-path nested-component test.
    #[test]
    fn packaging_rejects_core_modules_and_truncated_components() {
        assert!(with_metadata(&Module::new().finish(), b"{}").is_err());
        assert!(with_metadata(&[0, 97, 115, 109, 13, 0, 1, 0, 1, 127], b"{}").is_err());
    }

    // Registry admission reads static metadata before a host invokes the guest.
    // This checks the shipped WIT digest, strict option schema, rule identity and
    // filesystem requirement in the generated declaration. Drift in those fields
    // can reject a working component or hide the access its source analysis needs.
    #[test]
    fn declaration_uses_the_current_vendored_contract_and_rule_schema() -> Result<()> {
        let value: serde_json::Value = serde_json::from_slice(&metadata()?)?;
        assert_eq!(
            value["contract_sha256"],
            "a0096f562ab3da46b30d0f025ad1c6ed0d46e5b7ea1a53660b3214e3270fcbee"
        );
        assert_eq!(
            value["descriptor"]["options_schema"]["additionalProperties"],
            false
        );
        assert_eq!(value["descriptor"]["name"], "shellcheck-rs");
        assert_eq!(value["capabilities"]["filesystem"], true);
        Ok(())
    }
}
