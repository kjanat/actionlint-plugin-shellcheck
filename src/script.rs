use crate::exports::kjanat::actionlint::analyzer::{Position, Script};
use crate::kjanat::actionlint::prepared_scripts;

pub struct Prepared {
    pub data: prepared_scripts::Prepared,
}

#[cfg(target_arch = "wasm32")]
pub fn request(script: &Script, dialect: Option<&str>) -> Result<Option<Prepared>, String> {
    let reference = &script.reference;
    prepared_scripts::prepare(
        &crate::kjanat::actionlint::source_annotations::SourceReference {
            document: reference.document.clone(),
            revision: reference.revision.clone(),
            node: reference.node.clone(),
            address: reference.address.clone(),
        },
        dialect,
    )
    .map(|prepared| prepared.map(|data| Prepared { data }))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn request(_: &Script, _: Option<&str>) -> Result<Option<Prepared>, String> {
    Err("analysis requires the prepared-scripts host interface".to_string())
}

impl Prepared {
    fn line(&self, line: i64) -> Option<&prepared_scripts::Line> {
        usize::try_from(line.checked_sub(1)?)
            .ok()
            .and_then(|index| self.data.lines.get(index))
    }

    pub fn is_startup(&self, line: i64) -> bool {
        matches!(self.line(line), Some(prepared_scripts::Line::Startup))
    }

    pub fn comment_position(&self, line: i64, column: i64) -> Option<Position> {
        let prepared_scripts::Line::Comment(start) = self.line(line)? else {
            return None;
        };
        Some(Position {
            line: start.line,
            column: start
                .column
                .checked_add(u32::try_from(column).ok()?.checked_sub(1)?)?,
        })
    }

    pub fn original_line(&self, line: i64) -> u32 {
        if usize::try_from(line).ok() == self.data.lines.len().checked_add(1) {
            for source in self.data.lines.iter().rev() {
                if let prepared_scripts::Line::Script(source) = source {
                    return source.saturating_add(1);
                }
            }
        }
        match self.line(line) {
            Some(prepared_scripts::Line::Script(source)) => *source,
            _ => 0,
        }
    }

    pub fn lines(&self) -> Vec<&str> {
        self.data.text.split('\n').collect()
    }
}

fn real_column(line: &str, target: i64) -> i64 {
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
