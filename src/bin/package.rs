use std::error::Error;
use std::path::Path;

use actionlint_extension_api::package::Capabilities;
use actionlint_extension_api::package::Engine;
use actionlint_extension_api::package::Identity;
use actionlint_extension_api::package::Package;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [input, output] = args.as_slice() else {
        return Err("usage: package <component.wasm> <output-directory>".into());
    };
    Package {
        identity: Identity {
            name: "ShellCheck",
            description: env!("CARGO_PKG_DESCRIPTION"),
            license: env!("CARGO_PKG_LICENSE"),
            repository: env!("CARGO_PKG_REPOSITORY"),
            version: env!("CARGO_PKG_VERSION"),
        },
        engine: Engine {
            name: "shellcheck-rs",
            version: "1.0.0",
        },
        languages: &["shell"],
        capabilities: Capabilities {
            filesystem: true,
            network: false,
            fixes: true,
            source_annotations: true,
        },
        descriptor: &actionlint_plugin_shellcheck::descriptor(),
        license_text: include_str!("../../LICENSE"),
    }
    .write(Path::new(input), Path::new(output))
}
