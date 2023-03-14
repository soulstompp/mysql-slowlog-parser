//! # Parse MySQL SlowLog
//!
//! A pull parser library for reading MySQL's slow query logs.
extern crate core;

use std::collections::{BTreeSet, HashMap};
use std::default::Default;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

pub use crate::parser::{EntryAdminCommand, EntryStats, EntryTime, EntryUser, SqlStatementContext};

use iso8601::DateTime;
use sqlparser::ast::{visit_relations, Statement};
use std::ops::ControlFlow;

pub use crate::codec::{CodecError, EntryCodec, EntryError};

mod codec;
mod parser;

/// Error returned to cover all cases when reading/parsing a log
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("invalid time line: {0}")]
    InvalidTimeLine(String),
    #[error("invalid user line: {0}")]
    InvalidUserLine(String),
    #[error("invalid stats line: {0}")]
    InvalidStatsLine(String),
    #[error("invalid entry with invalid sql starting at end of file")]
    IncompleteSql,
    #[error("Invalid log format or format contains no entries")]
    IncompleteLog,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntrySqlStatement {
    pub statement: Statement,
    pub context: Option<SqlStatementContext>,
}

impl EntrySqlStatement {
    pub fn objects(&self) -> Vec<EntrySqlStatementObject> {
        let mut visited = BTreeSet::new();

        visit_relations(&self.statement, |relation| {
            let ident = &relation.0;

            let _ = visited.insert(if ident.len() == 2 {
                EntrySqlStatementObject {
                    schema_name: Some(ident[0].value.to_string()),
                    object_name: ident[1].value.to_string(),
                }
            } else {
                EntrySqlStatementObject {
                    schema_name: None,
                    object_name: ident.last().unwrap().value.to_string(),
                }
            });

            ControlFlow::<()>::Continue(())
        });
        visited.into_iter().collect()
    }

    pub fn entry_sql_type(&self) -> EntrySqlType {
        match self.statement {
            Statement::Query(_) => EntrySqlType::Query,
            Statement::Insert { .. } => EntrySqlType::Insert,
            Statement::Update { .. } => EntrySqlType::Update,
            Statement::Delete { .. } => EntrySqlType::Delete,
            Statement::CreateTable { .. } => EntrySqlType::CreateTable,
            Statement::CreateIndex { .. } => EntrySqlType::CreateIndex,
            Statement::CreateView { .. } => EntrySqlType::CreateView,
            Statement::AlterTable { .. } => EntrySqlType::AlterTable,
            Statement::AlterIndex { .. } => EntrySqlType::AlterIndex,
            Statement::Drop { .. } => EntrySqlType::Drop,
            Statement::DropFunction { .. } => EntrySqlType::DropFunction,
            Statement::SetVariable { .. } => EntrySqlType::SetVariable,
            Statement::SetNames { .. } => EntrySqlType::SetNames,
            Statement::SetNamesDefault { .. } => EntrySqlType::SetNamesDefault,
            Statement::ShowVariable { .. } => EntrySqlType::ShowVariable,
            Statement::ShowVariables { .. } => EntrySqlType::ShowVariables,
            Statement::ShowCreate { .. } => EntrySqlType::ShowCreate,
            Statement::ShowColumns { .. } => EntrySqlType::ShowColumns,
            Statement::ShowTables { .. } => EntrySqlType::ShowTables,
            Statement::ShowCollation { .. } => EntrySqlType::ShowCollation,
            Statement::Use { .. } => EntrySqlType::Use,
            Statement::StartTransaction { .. } => EntrySqlType::StartTransaction,
            Statement::SetTransaction { .. } => EntrySqlType::SetTransaction,
            Statement::Commit { .. } => EntrySqlType::Commit,
            Statement::Rollback { .. } => EntrySqlType::Rollback,
            Statement::CreateSchema { .. } => EntrySqlType::CreateSchema,
            Statement::CreateDatabase { .. } => EntrySqlType::CreateDatabase,
            Statement::Grant { .. } => EntrySqlType::Grant,
            Statement::Revoke { .. } => EntrySqlType::Revoke,
            Statement::Kill { .. } => EntrySqlType::Kill,
            Statement::ExplainTable { .. } => EntrySqlType::ExplainTable,
            Statement::Explain { .. } => EntrySqlType::Explain,
            Statement::Savepoint { .. } => EntrySqlType::Savepoint,
            _ => panic!("sql types for MySQL should be exhaustive"),
        }
    }
}

impl From<Statement> for EntrySqlStatement {
    fn from(statement: Statement) -> Self {
        EntrySqlStatement {
            statement,
            context: None,
        }
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

/// The SQL statement type of the EntrySqlStatement.
///
/// NOTE: this is a MySQL specific sub-set of the entries in `sql_parser::ast::Statement`. This is
/// a simpler enum to match against and displays as the start of the SQL command.
#[derive(Clone, Debug, PartialEq)]
pub enum EntrySqlType {
    /// SELECT
    Query,
    /// INSERT
    Insert,
    /// UPDATE
    Update,
    /// DELETE
    Delete,
    /// CREATE TABLE
    CreateTable,
    /// CREATE INDEX
    CreateIndex,
    /// CREATE VIEW
    CreateView,
    /// ALTER TABLE
    AlterTable,
    /// ALTER INDEX
    AlterIndex,
    /// DROP TABLE
    Drop,
    /// DROP FUNCTION
    DropFunction,
    /// SET VARIABLE
    SetVariable,
    /// SET NAMES
    SetNames,
    /// SET NAMES DEFAULT
    SetNamesDefault,
    /// SHOW VARIABLE
    ShowVariable,
    /// SHOW VARIABLES
    ShowVariables,
    /// SHOW CREATE TABLE
    ShowCreate,
    /// SHOW COLUMNS
    ShowColumns,
    /// SHOW TABLES
    ShowTables,
    /// SHOW COLLATION
    ShowCollation,
    /// USE
    Use,
    /// BEGIN TRANSACTION
    StartTransaction,
    /// SET TRANSACTION
    SetTransaction,
    /// COMMIT TRANSACTION
    Commit,
    /// ROLLBACK TRANSACTION
    Rollback,
    /// CREATE SCHEMA
    CreateSchema,
    /// CREATE DATABASE
    CreateDatabase,
    /// GRANT
    Grant,
    /// REVOKE
    Revoke,
    /// KILL
    Kill,
    /// EXPLAIN TABLE
    ExplainTable,
    /// EXPLAIN
    Explain,
    /// SAVEPOINT
    Savepoint,
}

impl Display for EntrySqlType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            Self::Query => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::CreateTable => "CREATE TABLE",
            Self::CreateIndex => "CREATE INDEX",
            Self::CreateView => "CREATE VIEW",
            Self::AlterTable => "ALTER TABLE",
            Self::AlterIndex => "ALTER INDEX",
            Self::Drop => "DROP TABLE",
            Self::DropFunction => "DROP FUNCTION",
            Self::SetVariable => "SET VARIABLE",
            Self::SetNames => "SET NAMES",
            Self::SetNamesDefault => "SET NAMES DEFAULT",
            Self::ShowVariable => "SHOW VARIABLE",
            Self::ShowVariables => "SHOW VARIABLES",
            Self::ShowCreate => "SHOW CREATE TABLE",
            Self::ShowColumns => "SHOW COLUMNS",
            Self::ShowTables => "SHOW TABLES",
            Self::ShowCollation => "SHOW COLLATION",
            Self::Use => "USE",
            Self::StartTransaction => "BEGIN TRANSACTION",
            Self::SetTransaction => "SET TRANSACTION",
            Self::Commit => "COMMIT TRANSACTION",
            Self::Rollback => "ROLLBACK TRANSACTION",
            Self::CreateSchema => "CREATE SCHEMA",
            Self::CreateDatabase => "CREATE DATABASE",
            Self::Grant => "GRANT",
            Self::Revoke => "REVOKE",
            Self::Kill => "KILL",
            Self::ExplainTable => "EXPLAIN TABLE",
            Self::Explain => "EXPLAIN",
            Self::Savepoint => "SAVEPOINT",
        };

        write!(f, "{}", out)
    }
}

/// types of masking to apply when parsing SQL statements
/// * PlaceHolder - mask all sql values with a '?' placeholder
/// * None - leave all values in place
#[derive(Clone, Debug, PartialEq)]
pub enum EntryMasking {
    PlaceHolder,
    None,
}

impl Default for EntryMasking {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Default)]
pub struct ReaderConfig {
    pub masking: EntryMasking,
    pub map_comment_context:
        Option<Box<dyn Fn(HashMap<String, String>) -> Option<SqlStatementContext>>>,
}

impl Debug for ReaderConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.masking)?;
        write!(f, "map_comment_context: fn")
    }
}

#[derive(Error, Debug)]
pub enum ReaderBuildError {
    #[error("reader must be set to build Reader")]
    MissingReader,
}

/// a struct representing the values parsed from the log entry
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    time: DateTime,
    start_timestamp: u32,
    user: String,
    sys_user: String,
    host: Option<String>,
    ip_address: Option<String>,
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
    pub fn host(&self) -> Option<String> {
        self.host.clone()
    }

    /// returns the ip address which requested the command
    pub fn ip_address(&self) -> Option<String> {
        self.ip_address.clone()
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

    pub fn statement(&self) -> EntryStatement {
        self.statement.clone()
    }
}
