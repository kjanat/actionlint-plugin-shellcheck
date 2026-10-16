const SET_FLAGS: &str = "abefhkmnptuvxBCEHPT";

pub fn analysis(name: &str, implicit: bool) -> (String, String) {
    let (command, arguments) = name.split_once(' ').unwrap_or((name, ""));
    let normalized = command.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("");
    let dialect = base.to_lowercase();
    let dialect = dialect.strip_suffix(".exe").unwrap_or(&dialect).to_string();
    if !matches!(dialect.as_str(), "bash" | "sh" | "dash" | "ksh") {
        return (String::new(), String::new());
    }
    if arguments.trim().is_empty() {
        if !command.eq_ignore_ascii_case("bash") && !command.eq_ignore_ascii_case("sh") {
            return (dialect, String::new());
        }
        if dialect == "bash" && !implicit {
            return (dialect, "set -e -o pipefail".to_string());
        }
        return (dialect, "set -e".to_string());
    }
    let args: Vec<&str> = arguments.split_whitespace().collect();
    for arg in &args {
        let arg = arg.trim_matches(|c| c == '\'' || c == '"');
        if arg == "{0}" || arg == "--" {
            break;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(['c', 's']) {
            return (String::new(), String::new());
        }
    }
    if arguments.contains("${{") || arguments.contains(['\'', '"', '\\']) {
        return (dialect, String::new());
    }
    let mut options: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "{0}" || arg == "--" {
            if arg == "--" && args.get(i + 1) != Some(&"{0}") {
                return (String::new(), String::new());
            }
            return (dialect, startup_options(&options));
        }
        if dialect == "bash" && (arg == "--noprofile" || arg == "--norc") {
            i += 1;
            continue;
        }
        if arg.len() > 1 && (arg.starts_with('-') || arg.starts_with('+')) {
            let sign = &arg[..1];
            let flags = &arg[1..];
            if let Some(before) = flags.strip_suffix('o') {
                i += 1;
                if i >= args.len() || !set_option(args[i]) {
                    return (dialect, String::new());
                }
                if !before.chars().all(|c| SET_FLAGS.contains(c)) {
                    return (dialect, String::new());
                }
                if !before.is_empty() {
                    options.push(format!("{sign}{before}"));
                }
                options.push(format!("{sign}o"));
                options.push(args[i].to_string());
            } else {
                if !flags.chars().all(|c| SET_FLAGS.contains(c)) {
                    return (dialect, String::new());
                }
                options.push(arg.to_string());
            }
            i += 1;
            continue;
        }
        return (String::new(), String::new());
    }
    (dialect, String::new())
}

fn alias(option: &str) -> &str {
    match option {
        "allexport" => "a",
        "errexit" => "e",
        "errtrace" => "E",
        "functrace" => "T",
        "noclobber" => "C",
        "noexec" => "n",
        "noglob" => "f",
        "nounset" => "u",
        "verbose" => "v",
        "xtrace" => "x",
        other => other,
    }
}

fn startup_options(options: &[String]) -> String {
    let mut states: Vec<(String, bool)> = Vec::new();
    let mut set = |option: &str, enabled: bool| {
        let option = alias(option);
        match states.iter_mut().find(|(name, _)| name == option) {
            Some(state) => state.1 = enabled,
            None => states.push((option.to_string(), enabled)),
        }
    };
    let mut i = 0;
    while i < options.len() {
        let option = &options[i];
        let enabled = option.starts_with('-');
        if &option[1..] == "o" {
            i += 1;
            set(&options[i], enabled);
        } else {
            for flag in option[1..].chars() {
                set(&flag.to_string(), enabled);
            }
        }
        i += 1;
    }
    let mut flags = String::new();
    let mut named = Vec::new();
    for (option, enabled) in &states {
        if !enabled {
            continue;
        }
        if option.len() == 1 {
            flags.push_str(option);
        } else {
            named.push("-o".to_string());
            named.push(option.clone());
        }
    }
    let mut args = Vec::new();
    if !flags.is_empty() {
        args.push(format!("-{flags}"));
    }
    args.extend(named);
    if args.is_empty() {
        return String::new();
    }
    format!("set {}", args.join(" "))
}

fn set_option(option: &str) -> bool {
    matches!(
        option,
        "allexport"
            | "errexit"
            | "errtrace"
            | "functrace"
            | "noclobber"
            | "noexec"
            | "noglob"
            | "nounset"
            | "pipefail"
            | "posix"
            | "verbose"
            | "xtrace"
    )
}

#[cfg(test)]
mod tests {
    use super::analysis;

    #[test]
    fn startup_matches_the_host() {
        for (name, setup, implicit) in [
            ("bash", "set -e", true),
            ("bash", "set -e -o pipefail", false),
            ("BASH", "set -e -o pipefail", false),
            ("sh", "set -e", true),
            ("bash {0}", "", false),
            ("bash -e {0}", "set -e", false),
            ("bash -eu -o pipefail {0}", "set -eu -o pipefail", false),
            ("bash -euxo pipefail {0}", "set -eux -o pipefail", false),
            (
                "/usr/bin/bash -euxo pipefail {0}",
                "set -eux -o pipefail",
                false,
            ),
            (
                r"C:\tools\bash.exe -eo pipefail {0}",
                "set -e -o pipefail",
                false,
            ),
            ("dash -eu {0}", "set -eu", false),
            ("ksh -eu {0}", "set -eu", false),
            ("bash -euo pipefail +e +o pipefail {0}", "set -u", false),
            ("bash -o errexit +e {0}", "", false),
            ("bash -e +o errexit {0}", "", false),
            ("bash +e -o errexit {0}", "set -e", false),
            ("bash -e -- {0}", "set -e", false),
            ("bash -o noglob {0}", "set -f", false),
            ("bash -o future-option {0}", "", false),
            ("bash -e +e {0}", "", false),
            ("bash -o 'pipefail' {0}", "", false),
            ("bash -o \"pipefail\" {0}", "", false),
            ("bash ${{ vars.FLAGS }} {0}", "", false),
            ("bash --rcfile custom {0}", "", false),
            ("bash {0} -e", "", false),
        ] {
            let (dialect, got) = analysis(name, implicit);
            assert!(!dialect.is_empty(), "{name}: no dialect");
            assert_eq!(got, setup, "{name}");
        }
    }

    #[test]
    fn unknown_languages_are_skipped() {
        for name in [
            "bash -c 'python {0}'",
            "bash -ec 'python {0}'",
            "bash -s {0}",
            "bash \"-c\" \"python {0}\"",
            "python {0}",
            "pwsh {0}",
            "actions-shell python {0}",
            "wrapper bash {0}",
            "bash other-script {0}",
            "bash -- other-script {0}",
            "",
            "pwsh",
        ] {
            assert_eq!(
                analysis(name, false),
                (String::new(), String::new()),
                "{name}"
            );
        }
    }
}
