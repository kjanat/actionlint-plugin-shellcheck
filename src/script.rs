use std::sync::LazyLock;

use regex::Regex;

static SHELL_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r##"^[\t ]*#[\t ]*shellcheck[\t ]+(?:[a-z-]+=(?:"[^"\r\n]*"|'[^'\r\n]*'|[^'"#\t \r\n][^#\t \r\n]*)[\t ]+)*?shell="##)
        .unwrap_or_else(|error| panic!("shell directive pattern: {error}"))
});

pub fn header(source: &str) -> (&str, &str, bool) {
    let mut end = 0;
    let mut selects_shell = false;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            break;
        }
        selects_shell = selects_shell || SHELL_DIRECTIVE.is_match(line);
        end += line.len();
    }
    (&source[..end], &source[end..], selects_shell)
}

pub fn header_dialect(header: &str) -> String {
    for line in header.split('\n') {
        let Some(selector) = SHELL_DIRECTIVE.find(line) else {
            continue;
        };
        let value = line[selector.end()..]
            .strip_suffix('\r')
            .unwrap_or(&line[selector.end()..]);
        if let Some(quote) = value.chars().next().filter(|c| *c == '\'' || *c == '"') {
            return match value[1..].split_once(quote) {
                Some((dialect, _)) => dialect.to_string(),
                None => String::new(),
            };
        }
        return value.split(' ').next().unwrap_or("").to_string();
    }
    String::new()
}

pub fn sanitize_expressions(source: &str) -> String {
    let mut out = String::new();
    let mut rest = source;
    loop {
        let Some(start) = rest.find("${{") else {
            if out.is_empty() {
                return source.to_string();
            }
            out.push_str(rest);
            return out;
        };
        let Some(end) = rest[start..].find("}}") else {
            if out.is_empty() {
                return source.to_string();
            }
            out.push_str(rest);
            return out;
        };
        let end = start + end + 2;
        out.push_str(&rest[..start]);
        for c in rest[start..end].chars() {
            out.push(if c == '\n' || c == '\r' { c } else { '_' });
        }
        rest = &rest[end..];
    }
}

pub struct Prepared {
    pub text: String,
    source_lines: Vec<u32>,
    pub startup_line: usize,
}

pub fn prepare(source: &str, setup: &str) -> Prepared {
    let (mut header, body, _) = header(source);
    let mut text = String::new();
    let mut source_lines = Vec::new();
    let mut original = 0;
    let mut write_source = |piece: &str, text: &mut String, source_lines: &mut Vec<u32>| {
        for line in piece.split_inclusive('\n') {
            if line.is_empty() {
                continue;
            }
            original += 1;
            source_lines.push(original);
            text.push_str(line);
            if !line.ends_with('\n') {
                text.push('\n');
            }
        }
    };
    if header.starts_with("#!") {
        let (line, rest) = match header.split_once('\n') {
            Some((line, rest)) => (&header[..line.len() + 1], rest),
            None => (header, ""),
        };
        write_source(line, &mut text, &mut source_lines);
        header = rest;
    }
    write_source(header, &mut text, &mut source_lines);
    let mut startup_line = 0;
    if !setup.is_empty() {
        text.push_str(setup);
        text.push('\n');
        source_lines.push(0);
        startup_line = source_lines.len();
    }
    write_source(body, &mut text, &mut source_lines);
    if text.is_empty() {
        text.push('\n');
        source_lines.push(0);
    }
    Prepared {
        text,
        source_lines,
        startup_line,
    }
}

impl Prepared {
    pub fn original_line(&self, line: i64) -> u32 {
        if line == self.source_lines.len() as i64 + 1 {
            for source in self.source_lines.iter().rev() {
                if *source != 0 {
                    return source + 1;
                }
            }
        }
        if line < 1 || line > self.source_lines.len() as i64 {
            return 0;
        }
        self.source_lines[line as usize - 1]
    }

    pub fn lines(&self) -> Vec<&str> {
        self.text.split('\n').collect()
    }
}

pub fn real_column(line: &str, target: i64) -> i64 {
    let mut real: i64 = 0;
    let mut virtual_column: i64 = 0;
    for c in line.chars() {
        if target <= virtual_column {
            return real;
        }
        if c == '\t' {
            virtual_column += 8 - (virtual_column % 8);
        } else {
            virtual_column += 1;
        }
        real += 1;
    }
    if target <= virtual_column {
        return real;
    }
    real + (target - virtual_column)
}

pub fn realign(lines: &[&str], line: i64, column: i64) -> i64 {
    usize::try_from(line - 1)
        .ok()
        .and_then(|index| lines.get(index))
        .map_or(column, |text| real_column(text, column))
}

#[cfg(test)]
mod tests {
    use super::header;
    use super::header_dialect;
    use super::prepare;
    use super::real_column;
    use super::sanitize_expressions;

    #[test]
    fn header_detects_shell_directives() {
        let (head, body, selects) =
            header("#!/bin/sh\n# shellcheck disable=SC2086 shell=dash\n\necho hi\n");
        assert_eq!(
            head,
            "#!/bin/sh\n# shellcheck disable=SC2086 shell=dash\n\n"
        );
        assert_eq!(body, "echo hi\n");
        assert!(selects);
        assert_eq!(header_dialect(head), "dash");
        assert_eq!(header_dialect("# shellcheck shell='ksh'\n"), "ksh");
        assert_eq!(
            header_dialect("# shellcheck shell=\"bash\" disable=SC1\n"),
            "bash"
        );
        assert_eq!(header_dialect("# shellcheck shell='unclosed\n"), "");
        let (head, body, selects) = header("echo hi\n# shellcheck shell=sh\n");
        assert_eq!(
            (head, body, selects),
            ("", "echo hi\n# shellcheck shell=sh\n", false)
        );
    }

    #[test]
    fn expressions_become_underscores() {
        assert_eq!(
            sanitize_expressions("echo ${{ matrix.os }} done"),
            "echo ________________ done"
        );
        assert_eq!(
            sanitize_expressions("if ${{ a\n}}; then"),
            "if _____\n__; then"
        );
        assert_eq!(sanitize_expressions("plain ${{ open"), "plain ${{ open");
    }

    #[test]
    fn prepared_scripts_map_back_to_source_lines() {
        let prepared = prepare("#!/bin/bash\n# comment\necho one\necho two", "set -e");
        assert_eq!(
            prepared.text,
            "#!/bin/bash\n# comment\nset -e\necho one\necho two\n"
        );
        assert_eq!(prepared.startup_line, 3);
        assert_eq!(
            (1..=6)
                .map(|line| prepared.original_line(line))
                .collect::<Vec<_>>(),
            vec![1, 2, 0, 3, 4, 5]
        );
        assert_eq!(prepared.original_line(7), 0);
        let empty = prepare("", "");
        assert_eq!(empty.text, "\n");
        assert_eq!(empty.original_line(1), 0);
    }

    #[test]
    fn tab_columns_realign() {
        assert_eq!(real_column("\techo $x", 9), 2);
        assert_eq!(real_column("\techo $x", 14), 7);
        assert_eq!(real_column("echo", 3), 3);
        assert_eq!(real_column("a\t", 5), 2);
        assert_eq!(real_column("a\t", 9), 3);
        assert_eq!(real_column("ab", 5), 5);
    }
}
