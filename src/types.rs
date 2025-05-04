use crate::{EntryAdminCommand, SessionLine, SqlStatementContext, StatsLine};
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::{visit_relations, Statement};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::ops::ControlFlow;
use winnow_datetime::DateTime;

/// a struct representing a single log entry
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// holds information about the call made to mysqld
    pub call: EntryCall,
    /// holds information about the connection that made the call
    pub session: EntrySession,
    /// stats about how long it took for the query to run
    pub stats: EntryStats,
    /// information obtained while parsing the SQL query
    pub sql_attributes: EntrySqlAttributes,
}

impl Entry {
    /// returns the time the entry was recorded
    pub fn log_time(&self) -> DateTime {
        self.call.log_time
    }

    /// returns the mysql user name that requested the command
    pub fn user_name(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.session.user_name)
    }

    /// returns the mysql user name that requested the command
    pub fn user_name_bytes(&self) -> Bytes {
        self.session.user_name.clone()
    }

    /// returns the system user name that requested the command
    pub fn sys_user_name(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.session.sys_user_name)
    }

    /// returns the system user name that requested the command
    pub fn sys_user_name_bytes(&self) -> Bytes {
        self.session.sys_user_name.clone()
    }

    /// returns the host name which requested the command
    pub fn host_name(&self) -> Option<Cow<str>> {
        if let Some(v) = &self.session.host_name {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the host name which requested the command
    pub fn host_name_bytes(&self) -> Option<Bytes> {
        self.session.host_name_bytes()
    }

    /// returns the ip address which requested the command
    pub fn ip_address(&self) -> Option<Cow<'_, str>> {
        self.session.ip_address()
    }

    /// returns the ip address which requested the command
    pub fn ip_address_bytes(&self) -> Option<Bytes> {
        self.session.ip_address_bytes()
    }

    /// returns the the thread id of the session which requested the command
    pub fn thread_id(&self) -> u32 {
        self.session.thread_id()
    }

    /// returns a ref to the entry's EntryStats struct
    pub fn stats(&self) -> &EntryStats {
        &self.stats
    }

    /// returns how long the query took to run
    pub fn query_time(&self) -> f64 {
        self.stats.query_time()
    }

    /// returns how long it took to lock
    pub fn lock_time(&self) -> f64 {
        self.stats.lock_time()
    }

    /// returns number of rows returned when query was executed
    pub fn rows_sent(&self) -> u32 {
        self.stats.rows_sent()
    }

    /// returns how many rows where examined to execute the query
    pub fn rows_examined(&self) -> u32 {
        self.stats.rows_examined()
    }
}

#[derive(Clone, Debug, PartialEq)]
///
pub struct EntrySqlStatement {
    /// Holds the Statement
    pub statement: Statement,
    pub context: Option<SqlStatementContext>,
}

impl EntrySqlStatement {
    pub fn sql_context(&self) -> Option<SqlStatementContext> {
        self.context.clone()
    }

    pub fn objects(&self) -> Vec<EntrySqlStatementObject> {
        let mut visited = BTreeSet::new();

        visit_relations(&self.statement, |relation| {
            let ident = &relation.0;

            let _ = visited.insert(if ident.len() == 2 {
                EntrySqlStatementObject {
                    schema_name: Some(ident[0].value.to_owned().into()),
                    object_name: ident[1].value.to_owned().into(),
                }
            } else {
                EntrySqlStatementObject {
                    schema_name: None,
                    object_name: ident.last().unwrap().value.to_owned().into(),
                }
            });

            ControlFlow::<()>::Continue(())
        });
        visited.into_iter().collect()
    }

    pub fn sql_type(&self) -> EntrySqlType {
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
            Statement::LockTables { .. } => EntrySqlType::LockTables,
            Statement::UnlockTables { .. } => EntrySqlType::LockTables,
            Statement::Flush { .. } => EntrySqlType::Flush,
            _ => EntrySqlType::Unknown,
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

/// Database objects called from within a query
#[derive(Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct EntrySqlStatementObject {
    /// optional schema name
    pub schema_name: Option<Bytes>,
    /// object name (i.e. table name)
    pub object_name: Bytes,
}

impl EntrySqlStatementObject {
    /// returns the optional schema name of object
    pub fn schema_name(&self) -> Option<Cow<str>> {
        if let Some(v) = &self.schema_name {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the optional schema name of object as bytes
    pub fn schema_name_bytes(&self) -> Option<Bytes> {
        self.schema_name.clone()
    }

    /// returns the object name of object
    pub fn object_name(&self) -> Cow<str> {
        String::from_utf8_lossy(self.object_name.as_ref())
    }

    /// returns the object name of object as bytes
    pub fn object_name_bytes(&self) -> Bytes {
        self.object_name.clone()
    }

    /// full object name \[schema.\]object in Bytes
    pub fn full_object_name_bytes(&self) -> Bytes {
        let mut s = if let Some(n) = self.schema_name.clone() {
            let mut s = BytesMut::from(n.as_ref());
            s.put_slice(b".");
            s
        } else {
            BytesMut::new()
        };

        s.put_slice(self.object_name.as_ref());
        s.freeze()
    }

    /// full object name \[schema.\]object as a CoW
    pub fn full_object_name(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.full_object_name_bytes().as_ref())
            .to_string()
            .into()
    }
}

/// Types of possible statements parsed from the log:
/// * SqlStatement: parseable statement with a proper SQL AST
/// * AdminCommand: commands passed from the mysql cli/admin tools
/// * InvalidStatement: statement which isn't currently parseable as plain-text
#[derive(Clone, Debug, PartialEq)]
pub enum EntryStatement {
    /// AdminCommand: commands passed from the mysql cli/admin tools
    AdminCommand(EntryAdminCommand),
    /// SqlStatement: parseable statement with a proper SQL AST
    SqlStatement(EntrySqlStatement),
    /// InvalidStatement: statement which isn't currently parseable by `sql-parser` crate
    InvalidStatement(String),
}

impl EntryStatement {
    /// returns the `EntrySqlStatement` objects associated with this statement, if known
    pub fn objects(&self) -> Option<Vec<EntrySqlStatementObject>> {
        match self {
            Self::SqlStatement(s) => Some(s.objects().clone()),
            _ => None,
        }
    }

    /// returns the `EntrySqlType` associated with this statement if known
    pub fn sql_type(&self) -> Option<EntrySqlType> {
        match self {
            Self::SqlStatement(s) => Some(s.sql_type().clone()),
            _ => None,
        }
    }

    /// returns the `SqlStatementContext` associated with this statement
    pub fn sql_context(&self) -> Option<SqlStatementContext> {
        match self {
            Self::SqlStatement(s) => s.sql_context().clone(),
            _ => None,
        }
    }
}

/// The SQL statement type of the EntrySqlStatement.
///
/// NOTE: this is a MySQL specific sub-set of the entries in `sql_parser::ast::Statement`. This is
/// a simpler enum to match against and displays as the start of the SQL command.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
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
    /// LOCK TABLES
    LockTables,
    /// UNLOCK TABLES
    UnlockTables,
    /// FLUSH
    Flush,
    /// Unable to identy if the type of statement
    Unknown,
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
            Self::LockTables => "LOCK TABLES",
            Self::UnlockTables => "UNLOCK TABLES",
            Self::Flush => "FLUSH",
            Self::Unknown => "NULL",
        };

        write!(f, "{}", out)
    }
}

/// struct containing information about the connection where the query originated
#[derive(Clone, Debug, PartialEq)]
pub struct EntrySession {
    /// user name of the connected user who ran the query
    pub user_name: Bytes,
    /// system user name of the connected user who ran the query
    pub sys_user_name: Bytes,
    /// hostname of the connected user who ran the query
    pub host_name: Option<Bytes>,
    /// ip address of the connected user who ran the query
    pub ip_address: Option<Bytes>,
    /// the thread id that the session was conntected on
    pub thread_id: u32,
}

impl From<SessionLine> for EntrySession {
    fn from(line: SessionLine) -> Self {
        Self {
            user_name: line.user,
            sys_user_name: line.sys_user,
            host_name: line.host,
            ip_address: line.ip_address,
            thread_id: line.thread_id,
        }
    }
}

impl EntrySession {
    /// returns the mysql user name that requested the command
    pub fn user_name(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.user_name)
    }

    /// returns the mysql user name that requested the command
    pub fn user_name_bytes(&self) -> Bytes {
        self.user_name.clone()
    }

    /// returns the system user name that requested the command
    pub fn sys_user_name(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.sys_user_name)
    }

    /// returns the system user name that requested the command
    pub fn sys_user_name_bytes(&self) -> Bytes {
        self.sys_user_name.clone()
    }

    /// returns the host name which requested the command
    pub fn host_name(&self) -> Option<Cow<str>> {
        if let Some(v) = &self.host_name {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the host name which requested the command
    pub fn host_name_bytes(&self) -> Option<Bytes> {
        self.host_name.clone()
    }

    /// returns the ip address which requested the command
    pub fn ip_address(&self) -> Option<Cow<'_, str>> {
        if let Some(v) = &self.ip_address {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the ip address which requested the command
    pub fn ip_address_bytes(&self) -> Option<Bytes> {
        self.ip_address.clone()
    }

    /// returns the the thread id of the which requested the command
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }
}

/// struct with information about the Entry's SQL query
#[derive(Clone, Debug, PartialEq)]
pub struct EntrySqlAttributes {
    /// the sql for this entry, possibly with values replaced by parameters
    pub sql: Bytes,
    /// the `EntryStatement for this entry
    pub statement: EntryStatement,
}

impl EntrySqlAttributes {
    /// returns the sql statement as bytes
    pub fn sql_bytes(&self) -> Bytes {
        self.sql.clone()
    }

    /// returns the ip address which requested the command
    pub fn sql(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.sql.as_ref())
    }

    /// returns the ip address which requested the command
    pub fn sql_type(&self) -> Option<EntrySqlType> {
        self.statement.sql_type()
    }

    /// returns entry sql statment objects
    pub fn objects(&self) -> Option<Vec<EntrySqlStatementObject>> {
        self.statement.objects()
    }

    /// returns the entry's `EntryStatement`
    pub fn statement(&self) -> &EntryStatement {
        &self.statement
    }
}

/// struct containing details of how long the query took
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EntryCall {
    /// time recorded for the log entry
    pub log_time: DateTime,
    /// effective time of NOW() during the query run
    pub set_timestamp: u32,
}

impl EntryCall {
    /// create a new instance of EntryCall
    pub fn new(log_time: DateTime, set_timestamp: u32) -> Self {
        Self {
            log_time,
            set_timestamp,
        }
    }

    /// returns the entry time as an `DateTime`
    pub fn log_time(&self) -> DateTime {
        self.log_time
    }

    /// returns the time stamp set at the beginning of each entry
    pub fn set_timestamp(&self) -> u32 {
        self.set_timestamp
    }
}

/// struct with stats on how long a query took and number of rows examined
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct EntryStats {
    /// how long the query took
    pub query_time: f64,
    /// how long the query held locks
    pub lock_time: f64,
    /// how many rows were returned to the client
    pub rows_sent: u32,
    /// how many rows were scanned to find result
    pub rows_examined: u32,
}

impl EntryStats {
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
}

impl From<StatsLine> for EntryStats {
    fn from(line: StatsLine) -> Self {
        Self {
            query_time: line.query_time,
            lock_time: line.lock_time,
            rows_sent: line.rows_sent,
            rows_examined: line.rows_examined,
        }
    }
}

/// Values parsed from a query comment, these values are currently overly-specific
#[derive(Clone, Debug, PartialEq)]
pub struct EntryContext {
    /// optional request id, such as an SSRID
    pub request_id: Option<Bytes>,
    /// optional caller
    pub caller: Option<Bytes>,
    /// optional function/method
    pub function: Option<Bytes>,
    /// optional line number
    pub line: Option<u32>,
}

impl EntryContext {
    /// returns the request_id from query comment
    pub fn request_id(&self) -> Option<Cow<str>> {
        if let Some(v) = &self.request_id {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the request_id from query comment
    pub fn request_id_bytes(&self) -> Option<Bytes> {
        self.request_id.clone()
    }

    /// returns the caller from query comment
    pub fn caller(&self) -> Option<Cow<str>> {
        if let Some(v) = &self.caller {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the caller from query comment
    pub fn caller_bytes(&self) -> Option<Bytes> {
        self.caller.clone()
    }

    /// returns the function from query comment
    pub fn function(&self) -> Option<Cow<str>> {
        if let Some(v) = &self.function {
            Some(String::from_utf8_lossy(v.as_ref()))
        } else {
            None
        }
    }

    /// returns the function from query comment
    pub fn function_bytes(&self) -> Option<Bytes> {
        self.function.clone()
    }

    /// returns the line from query comment
    pub fn line(&self) -> Option<u32> {
        self.line
    }
}
