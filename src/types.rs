use crate::{EntryAdminCommand, SessionLine, SqlStatementContext, StatsLine};
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::{visit_relations, Statement};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::ops::ControlFlow;
use time::{Duration, OffsetDateTime};

/// a struct representing the values parsed from the log entry
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub call: EntryCall,
    pub session: EntrySession,
    pub stats: EntryStats,
    pub sql_attributes: EntrySqlAttributes,
}

impl Entry {
    /// returns the time the entry was recorded
    pub fn log_time(&self) -> OffsetDateTime {
        self.call.log_time
    }

    pub fn query_start_time(&self) -> OffsetDateTime {
        self.call.start_time()
    }

    pub fn query_lock_end_time(&self) -> OffsetDateTime {
        self.call.lock_end_time()
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
pub struct EntrySqlStatement {
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
    pub schema_name: Option<Bytes>,
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
    AdminCommand(EntryAdminCommand),
    SqlStatement(EntrySqlStatement),
    InvalidStatement(String),
}

impl EntryStatement {
    pub fn objects(&self) -> Option<Vec<EntrySqlStatementObject>> {
        match self {
            Self::SqlStatement(s) => Some(s.objects().clone()),
            _ => None,
        }
    }

    pub fn sql_type(&self) -> Option<EntrySqlType> {
        match self {
            Self::SqlStatement(s) => Some(s.sql_type().clone()),
            _ => None,
        }
    }

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

#[derive(Clone, Debug, PartialEq)]
pub struct EntrySession {
    pub user_name: Bytes,
    pub sys_user_name: Bytes,
    pub host_name: Option<Bytes>,
    pub ip_address: Option<Bytes>,
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

#[derive(Clone, Debug, PartialEq)]
pub struct EntrySqlAttributes {
    pub sql: Bytes,
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

    pub fn statement(&self) -> &EntryStatement {
        &self.statement
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntryCall {
    pub log_time: OffsetDateTime,
    pub set_timestamp: OffsetDateTime,
    pub start_time: OffsetDateTime,
    pub lock_end_time: OffsetDateTime,
}

impl EntryCall {
    pub fn new(
        log_time: OffsetDateTime,
        set_timestamp: OffsetDateTime,
        query_time: f64,
        lock_time: f64,
    ) -> Self {
        Self {
            log_time,
            set_timestamp,
            start_time: log_time
                - Duration::microseconds(((lock_time + query_time) * 1_000_000.0).round() as i64),
            lock_end_time: log_time
                - Duration::microseconds((query_time * 1_000_000.0).round() as i64),
        }
    }

    /// returns the entry time as an `time::OffsetDateTime`
    pub fn log_time(&self) -> OffsetDateTime {
        self.log_time
    }

    /// returns the time stamp set at the beginning of each entry
    pub fn set_timestamp(&self) -> OffsetDateTime {
        self.set_timestamp
    }

    pub fn start_time(&self) -> OffsetDateTime {
        self.start_time
    }

    pub fn lock_end_time(&self) -> OffsetDateTime {
        self.lock_end_time
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct EntryStats {
    pub query_time: f64,
    pub lock_time: f64,
    pub rows_sent: u32,
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

#[derive(Clone, Debug, PartialEq)]
pub struct EntryContext {
    pub request_id: Option<Bytes>,
    pub caller: Option<Bytes>,
    pub function: Option<Bytes>,
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
