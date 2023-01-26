//! # Parse MySQL SlowLog
//!
//! A pull parser library for reading MySQL's slow query logs.
extern crate core;

use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

use crate::parser::{
    parse_admin_command, parse_details_comment, parse_entry_stats, parse_entry_time,
    parse_entry_user, parse_sql, parse_start_timestamp_command, EntryAdminCommand, EntryStats,
    EntryTime, EntryUser,
};
use crate::EntryError::MissingField;
use crate::EntryStatement::{AdminCommand, SqlStatement};
use crate::ReadError::{
    IncompleteEntry, IncompleteLog, IncompleteSql, InvalidStatsLine, InvalidTimeLine,
    InvalidUserLine,
};
use iso8601::DateTime;
use sqlparser::ast::{Statement, visit_relations};
use std::io;
use std::io::BufRead;
use std::ops::ControlFlow;

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
    #[error("found start of new entry before entry completed at line: {0}")]
    IncompleteEntry(EntryError),
    #[error("Invalid log format or format contains no entries")]
    IncompleteLog,
}

#[derive(Error, Debug)]
pub enum EntryError {
    #[error("entry is missing: {0}")]
    MissingField(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntrySqlStatement {
    pub statement: Statement,
    pub details: HashMap<String, String>,
}

impl EntrySqlStatement {
    pub fn objects(&self) -> Vec<EntrySqlStatementObject> {
        let mut visited = BTreeSet::new();

        visit_relations(&self.statement, |relation| {
            let ident = &relation.0;

             let _ = visited.insert(
                 if ident.len() == 2 {
                     EntrySqlStatementObject {
                         schema_name: Some(ident[0].value.to_string()),
                         object_name: ident[1].value.to_string(),
                     }
                 }
                     else {
                         EntrySqlStatementObject {
                             schema_name: None,
                             object_name: ident.last().unwrap().value.to_string(),
                         }
                     }

             );

            ControlFlow::<()>::Continue(())
        });
        visited.into_iter().collect()
    }
}

impl From<Statement> for EntrySqlStatement {
    fn from(statement: Statement) -> Self {
        let details = HashMap::new();

        EntrySqlStatement { statement, details }
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct EntrySqlStatementObject {
    pub schema_name: Option<String>,
    pub object_name: String,
}

/// Types of possible statements parsed from the log:
/// * SqlStatement: parseable statement with a proper SQL AST
/// * AdminCommand: commands passed from the mysql cli/admin tools
/// * InvalidStatement: statement which isn't currently parseable as plain-text
#[derive(Clone, Debug, PartialEq)]
pub enum EntryStatement {
    AdminCommand(EntryAdminCommand),
    SqlStatement(EntrySqlStatement),
    InvalidStatement(String),
}

/// context used internally for a Reader while parsing lines
#[derive(Default, Debug)]
struct EntryContext {
    time: Option<EntryTime>,
    user: Option<EntryUser>,
    stats: Option<EntryStats>,
    statement: Option<EntryStatement>,
    set_timestamp: Option<u32>,
}

impl EntryContext {
    fn entry(&self) -> Result<Entry, EntryError> {
        let time = self.time.clone().ok_or(MissingField("time".into()))?;
        let user = self.user.clone().ok_or(MissingField("user".into()))?;
        let stats = self.stats.clone().ok_or(MissingField("stats".into()))?;
        let set_timestamp = self
            .set_timestamp
            .clone()
            .ok_or(MissingField("set timestamp".into()))?;
        let statement = self.statement.clone().ok_or(MissingField("sql".into()))?;

        Ok(Entry {
            time: time.time(),
            start_timestamp: set_timestamp,
            user: user.user(),
            sys_user: user.sys_user(),
            host: user.host(),
            ip_address: user.ip_address().unwrap_or("127.0.0.1".into()),
            thread_id: user.thread_id(),
            query_time: stats.query_time(),
            lock_time: stats.lock_time(),
            rows_sent: stats.rows_sent(),
            rows_examined: stats.rows_examined(),
            statement,
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
    reader: &'a mut dyn BufRead,
    context: EntryContext,
    masking: EntryMasking,
    header: Option<String>,
}

impl<'a> Reader<'a> {
    pub fn new(reader: &'a mut dyn BufRead, m: EntryMasking) -> Result<Self, ReadError> {
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
                    if let Ok((_, timestamp)) = parse_start_timestamp_command(&l) {
                        if sql.len() == 0 {
                            self.context.set_timestamp = Some(timestamp);
                            continue;
                        }
                    }

                    sql.push_str(&l);

                    if let Ok((_, command)) = parse_admin_command(&l) {
                        self.context.statement = Some(EntryStatement::AdminCommand(command))
                    } else {
                        if let Ok(s) = parse_sql(&sql, &self.masking) {
                            if s.len() == 1 {
                                self.context.statement =
                                    Some(EntryStatement::SqlStatement(EntrySqlStatement {
                                        statement: s[0].clone(),
                                        details: details.take().unwrap_or(HashMap::new()),
                                    }))
                            } else {
                                self.context.statement = Some(EntryStatement::InvalidStatement(sql))
                            }
                        } else {
                            self.context.statement = Some(EntryStatement::InvalidStatement(sql))
                        }
                    }

                    sql = String::new();
                    details = None;

                    continue 'sql;
                }

                if l.starts_with("#") {
                    let e = self.context.entry().or_else(|e| Err(IncompleteEntry(e)))?;

                    self.start_entry(&l)?;

                    return Ok(Some(e));
                } else {
                    sql.push_str(&l);
                }
            } else {
                return if let Ok(e) = self.context.entry() {
                    Ok(Some(e))
                } else {
                    if self.context.statement.is_none() {
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
    start_timestamp: u32,
    user: String,
    sys_user: String,
    host: String,
    ip_address: String,
    thread_id: u32,
    query_time: f64,
    lock_time: f64,
    rows_sent: u32,
    rows_examined: u32,
    statement: EntryStatement,
}

impl Entry {
    /// return entry time as an `iso8601::DateTime`
    pub fn time(&self) -> DateTime {
        self.time
    }

    /// returns the time stamp set at the beginning of each entry
    pub fn start_timestamp(&self) -> u32 {
        self.start_timestamp
    }

    /// returns the mysql user name that requested the command
    pub fn user(&self) -> &str {
        &self.user
    }

    /// returns the system user name that requested the command
    pub fn sys_user(&self) -> &str {
        &self.sys_user
    }

    /// returns the host name which requested the command
    pub fn host(&self) -> &str {
        &self.host
    }

    /// returns the ip address which requested the command
    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }

    /// returns the the thread id of the session which requested the command
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// returns how long the query took to run
    pub fn query_time(&self) -> f64 {
        self.query_time
    }

    /// returns how long it took to lock
    pub fn lock_time(&self) -> f64 {
        self.lock_time
    }

    /// returns number of rows returned when query was executed
    pub fn rows_sent(&self) -> u32 {
        self.rows_sent
    }

    /// returns how many rows where examined to execute the query
    pub fn rows_examined(&self) -> u32 {
        self.rows_examined
    }

    /// returns `true` if entry contains valid SQL, otherwise `false`
    pub fn has_sql_statement(&self) -> bool {
        match &self.statement {
            SqlStatement(_) => true,
            _ => false,
        }
    }

    /// returns associated `&EntryStatement`
    pub fn statement(&self) -> &EntryStatement {
        &self.statement
    }

    /// returns `Some(&EntrySqlStatement)` if entry contains valid SQ, otherwise `None`
    pub fn sql_statement(&self) -> Option<&EntrySqlStatement> {
        match &self.statement {
            SqlStatement(s) => Some(s),
            _ => None,
        }
    }

    /// returns `true` if entry is an admin command, otherwise `false`
    pub fn has_admin_command(&self) -> bool {
        match &self.statement {
            AdminCommand(_) => true,
            _ => false,
        }
    }

    /// returns `Some(&EntryAdminCommand)` if entry is an admin command, otherwise `None`
    pub fn admin_command(&self) -> Option<&EntryAdminCommand> {
        match &self.statement {
            AdminCommand(ac) => Some(ac),
            _ => None,
        }
    }

    /// returns `true` if entry sql was unparseable, otherwise `false`
    pub fn has_invalid_statement(&self) -> bool {
        match &self.statement {
            EntryStatement::InvalidStatement(_) => true,
            _ => false,
        }
    }

    /// returns `Some(&str)` if entry sql was unparseable, otherwise `None`
    pub fn invalid_statement(&self) -> Option<&str> {
        match &self.statement {
            EntryStatement::InvalidStatement(is) => Some(is),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::EntryStatement::SqlStatement;
    use crate::{EntryMasking, EntrySqlStatementObject, Reader};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::BufReader;
    use std::ops::AddAssign;

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
            if let SqlStatement(s) = e.statement {
                assert_eq!(s.details, ed);
            } else {
                panic!("no statement")
            }
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
            if !e.has_sql_statement() {
                continue;
            }

            i.add_assign(1);

            res.push(e);
        }

        assert_eq!(res.len(), 2);
        assert_eq!(res[0], res[1]);
    }

    #[test]
    fn parse_select_objects() {
        let sql = String::from("# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT
JOIN film ON film_category.film_id = film.film_id LEFT JOIN film AS dupe_film ON film_category
.film_id = dupe_film.film_id LEFT JOIN other.film AS other_film ON other_film.film_id =
film_category.film_id
GROUP BY film.film_id, category.name;
");

        let mut b = sql.as_bytes();
        let mut r = Reader::new(&mut b, EntryMasking::None).unwrap();


        let e = r.read_entry().unwrap().unwrap();

        let expected = vec![
            EntrySqlStatementObject {
                schema_name: None,
                object_name: "category".to_string(),
            },
            EntrySqlStatementObject {
                schema_name: None,
                object_name: "film".to_string(),
            },
            EntrySqlStatementObject {
                schema_name: None,
                object_name: "film_category".to_string(),
            },
            EntrySqlStatementObject {
                schema_name: Some("other".to_string()),
                object_name: "film".to_string(),
            },
        ];

        match e.statement() {
            SqlStatement(s) => {
                assert_eq!(s.objects(), expected);
            }
            _ => { panic!("should have parsed sql as SqlStatement")}
        }
    }

    #[test]
    fn parse_slow_log() {
        let mut fr = BufReader::new(File::open("data/slow-test-queries.log").unwrap());
        let mut r = Reader::new(&mut fr, EntryMasking::PlaceHolder).unwrap();

        let mut i = 0usize;

        while let Some(_) = r.read_entry().unwrap() {
            i += 1;
        }

        assert_eq!(i, 310);
    }
}
