//! # Parse MySQL SlowLog
//!
//! A pull parser library for reading MySQL's slow query logs.
use std::collections::HashMap;
use thiserror::Error;

use crate::parser::{
    parse_admin_command, parse_details_comment, parse_entry_stats, parse_entry_time,
    parse_entry_user, parse_sql, EntryAdminCommand, EntryStats, EntryTime, EntryUser,
};
use crate::ReadError::{
    IncompleteEntry, IncompleteLog, IncompleteSql, InvalidStatsLine, InvalidTimeLine,
    InvalidUserLine,
};
use iso8601::DateTime;
use sqlparser::ast::Statement;
use std::io;
use std::io::{BufRead, BufReader, Read};

mod parser;

/// Error returned to cover all cases when reading/parsing a log
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("file read error: {0}")]
    IO(#[from] io::Error),
    #[error("invalid time line: {0}")]
    InvalidTimeLine(String),
    #[error("invalid user line: {0}")]
    InvalidUserLine(String),
    #[error("invalid stats line: {0}")]
    InvalidStatsLine(String),
    #[error("invalid entry with invalid sql starting at end of file")]
    IncompleteSql,
    #[error("{0} entry started but not completed at line: {1}")]
    IncompleteEntry(String, String),
    #[error("Invalid log format or format contains no entries")]
    IncompleteLog,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntrySqlStatement {
    statement: Statement,
    details: HashMap<String, String>,
}

impl From<Statement> for EntrySqlStatement {
    fn from(statement: Statement) -> Self {
        let details = HashMap::new();

        EntrySqlStatement { statement, details }
    }
}

/// Types of possible statements parsed from the log:
/// * SqlStatement: parseable statement with a proper SQL AST
/// * AdminCommand: commands passed from the mysql cli/admin tools
/// * InvalidStatement: statement which isn't currently parseable as plain-text
#[derive(Clone, Debug, PartialEq)]
pub enum EntryStatement {
    SqlStatement(EntrySqlStatement),
    AdminCommand(EntryAdminCommand),
    InvalidStatement(String),
}

/// context used internally for a Reader while parsing lines
#[derive(Default, Debug)]
struct EntryContext {
    time: Option<EntryTime>,
    user: Option<EntryUser>,
    stats: Option<EntryStats>,
    statements: Vec<EntryStatement>,
}

impl EntryContext {
    fn entry(&self) -> Result<Entry, ()> {
        let time = self.time.clone().ok_or(())?;
        let user = self.user.clone().ok_or(())?;
        let stats = self.stats.clone().ok_or(())?;

        Ok(Entry {
            time: time.time(),
            user: user.user(),
            sys_user: user.sys_user(),
            host: user.host(),
            query_time: stats.query_time(),
            lock_time: stats.lock_time(),
            rows_sent: stats.rows_sent(),
            rows_examined: stats.rows_examined(),
            statements: self.statements.clone(),
        })
    }

    fn started(&self) -> bool {
        self.time.is_some()
    }
}

/// types of masking to apply when parsing SQL statements
/// * PlaceHolder - mask all sql values with a '?' placeholder
/// * None - leave all values in place
#[derive(PartialEq)]
pub enum EntryMasking {
    PlaceHolder,
    None,
}

impl Default for EntryMasking {
    fn default() -> Self {
        Self::None
    }
}

pub struct Reader<'a> {
    reader: BufReader<&'a mut dyn Read>,
    context: EntryContext,
    masking: EntryMasking,
    header: Option<String>,
}

impl<'a> Reader<'a> {
    pub fn new(r: &'a mut dyn Read, m: EntryMasking) -> Result<Self, ReadError> {
        let reader = BufReader::new(r);

        Ok(Self {
            reader,
            context: Default::default(),
            masking: m,
            header: Default::default(),
        })
    }

    /// reads next line in BufReader returning None when there is nothing left to read
    fn read_line(&mut self) -> Result<Option<String>, ReadError> {
        let mut l = String::new();

        let bytes = self.reader.read_line(&mut l)?;

        if bytes == 0 {
            return Ok(None);
        }

        Ok(Some(l))
    }

    /// reads header section of an entry, currently parses the whole header as a String
    fn read_header(&mut self) -> Result<(), ReadError> {
        let mut h = String::new();

        loop {
            let line = self.read_line()?;

            if let Some(l) = line {
                if l.starts_with("#") {
                    self.start_entry(&l)?;
                    break;
                } else {
                    h.push_str(&l);
                }
            } else {
                return Err(ReadError::IncompleteLog);
            }
        }

        self.header = Some(h);

        Ok(())
    }

    /// reads the "# Time..." entry line which is the start of an entry, returns the entire header
    /// as a
    /// String
    ///
    /// *Note: this line sometimes contains an Id: [] portion which is discarded.*
    fn read_time(&mut self) -> Result<Option<()>, ReadError> {
        let line = self.read_line()?;

        if let Some(l) = line {
            if let Ok((_, t)) = parse_entry_time(&l) {
                self.context.time = Some(t);
            } else {
                return Err(InvalidTimeLine(l));
            }
        } else {
            return Ok(None);
        }

        Ok(Some(()))
    }

    /// reads the entry line containing statistics on the query
    fn read_stats(&mut self) -> Result<(), ReadError> {
        let line = self.read_line()?;

        if let Some(l) = line {
            if let Ok((_, s)) = parse_entry_stats(&l) {
                self.context.stats = Some(s);
            } else {
                return Err(InvalidStatsLine(l));
            }
        } else {
            return Err(InvalidStatsLine("".into()));
        }

        return Ok(());
    }

    /// reads the entry lines containing SQL and admistrator command statements
    fn read_sql(&mut self) -> Result<Option<Entry>, ReadError> {
        let mut sql = String::new();
        let mut details = None;

        'sql: loop {
            let line = self.read_line()?;

            if let Some(l) = line {
                if sql.len() == 0 {
                    if let Ok((_, d)) = parse_details_comment(&l) {
                        details = Some(d);
                    }
                }

                if l.trim().ends_with(";") {
                    sql.push_str(&l);

                    if let Ok((_, command)) = parse_admin_command(&l) {
                        self.context
                            .statements
                            .push(EntryStatement::AdminCommand(command))
                    } else {
                        if let Ok(s) = parse_sql(&sql, &self.masking) {
                            self.context.statements.append(
                                &mut s
                                    .into_iter()
                                    .map(|s| {
                                        EntryStatement::SqlStatement(EntrySqlStatement {
                                            statement: s,
                                            details: details.take().unwrap_or(HashMap::new()),
                                        })
                                    })
                                    .collect(),
                            )
                        } else {
                            self.context
                                .statements
                                .push(EntryStatement::InvalidStatement(sql))
                        }
                    }

                    sql = String::new();
                    details = None;

                    continue 'sql;
                }

                if l.starts_with("#") {
                    let e = self
                        .context
                        .entry()
                        .or(Err(IncompleteEntry("Sql".into(), l.clone())))?;

                    self.start_entry(&l)?;

                    return Ok(Some(e));
                } else {
                    sql.push_str(&l);
                }
            } else {
                return if let Ok(e) = self.context.entry() {
                    Ok(Some(e))
                } else {
                    if self.context.statements.is_empty() {
                        Err(IncompleteSql)
                    } else {
                        Ok(None)
                    }
                };
            }
        }
    }

    /// reads lines from BufReader and build
    ///
    /// *Note: the buffer is left at the start of the next entry, with a partially created entry
    /// stored in EntryContext. This partial which will be completed on the next call.*
    pub fn read_entry(&mut self) -> Result<Option<Entry>, ReadError> {
        if self.header.is_none() {
            self.read_header()?;
        }

        let mut line = None;

        if self.context.started() {
            line = self.read_line()?;

            if line.is_none() {
                return Ok(None);
            }
        } else {
            if self.read_time()?.is_none() {
                return Ok(None);
            }
        }

        if let Some(l) = line {
            if let Ok((_, u)) = parse_entry_user(&l) {
                self.context.user = Some(u);
            } else {
                return Err(InvalidUserLine(l));
            }
        } else {
            return Err(IncompleteLog);
        }

        self.read_stats()?;

        self.read_sql()
    }

    /// Parses the first line of an entry and resets `self.context` with only this initial value.
    fn start_entry(&mut self, l: &str) -> Result<(), ReadError> {
        if let Ok((_, t)) = parse_entry_time(&l) {
            self.context = EntryContext {
                time: Some(t),
                ..Default::default()
            };

            Ok(())
        } else {
            Err(InvalidTimeLine(l.into()))
        }
    }
}

/// a struct representing the values parsed from the log entry
#[derive(Debug, PartialEq)]
pub struct Entry {
    time: DateTime,
    user: String,
    sys_user: String,
    host: String,
    query_time: f64,
    lock_time: f64,
    rows_sent: u32,
    rows_examined: u32,
    statements: Vec<EntryStatement>,
}

#[cfg(test)]
mod tests {
    use crate::EntryStatement::SqlStatement;
    use crate::{Entry, EntryMasking, Reader};
    use std::collections::HashMap;
    use std::fs::File;
    use std::ops::AddAssign;

    fn test_entry(e: &Entry, c: usize) {
        assert_eq!(e.statements.len(), c, "statement count");
        assert!(
            e.statements.iter().all(|s| match s {
                SqlStatement(_) => true,
                _ => false,
            }),
            "all valid statements"
        );
    }

    #[test]
    fn parse_select_entry() {
        let sql = String::from("# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
-- ID: 123 caller: hello_world()
SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT JOIN film ON film_category.film_id = film.film_id
GROUP BY film.film_id, category.name;
");

        let mut b = sql.as_bytes();
        let mut r = Reader::new(&mut b, EntryMasking::None).unwrap();

        let ed = HashMap::from([
            ("ID".into(), "123".into()),
            ("caller".into(), "hello_world()".into()),
        ]);

        while let Some(e) = r.read_entry().unwrap() {
            if let SqlStatement(s) = &e.statements[1] {
                assert_eq!(s.details, ed);
            } else {
                panic!("expected a second statement")
            }

            test_entry(&e, 2);
        }
    }

    #[test]
    fn parse_select_entries() {
        let sql = String::from("# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT JOIN film ON film_category.film_id = film.film_id
GROUP BY film.film_id, category.name;
# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT JOIN film ON film_category.film_id = film.film_id
GROUP BY film.film_id, category.name;
");

        let mut b = sql.as_bytes();
        let mut r = Reader::new(&mut b, EntryMasking::None).unwrap();

        let mut i = 0usize;

        let mut res = vec![];

        while let Some(e) = r.read_entry().unwrap() {
            i.add_assign(1);
            test_entry(&e, 2);

            res.push(e);
        }

        assert_eq!(res.len(), 2);
        assert_eq!(res[0], res[1]);
    }

    #[test]
    fn parse_slow_log() {
        let mut f = File::open("data/slow-test-queries.log").unwrap();
        let mut p = Reader::new(&mut f, EntryMasking::PlaceHolder).unwrap();

        let mut i = 0usize;

        while let Some(_) = p.read_entry().unwrap() {
            i += 1;
        }

        assert_eq!(i, 310);
    }
}
