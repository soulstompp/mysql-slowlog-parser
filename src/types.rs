use crate::graph::StatementGraph;
use crate::parser::EntryLiteral;
use crate::{EntryAdminCommand, SessionLine, SqlStatementContext, StatsLine};
use bytes::{BufMut, Bytes, BytesMut};
use sqlparser::ast::{ObjectType, SetExpr, Statement, visit_relations};
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
        self.call.log_time.clone()
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

/// A statement the SQL parser accepted, with whatever the log's comment said about it.
#[derive(Clone, Debug, PartialEq)]
pub struct EntrySqlStatement {
    /// Holds the Statement
    pub statement: Statement,
    /// the key/value pairs of the comment preceding the statement, where there was one
    pub context: Option<SqlStatementContext>,
}

impl EntrySqlStatement {
    /// returns the key/value pairs parsed from the statement's preceding comment
    pub fn sql_context(&self) -> Option<SqlStatementContext> {
        self.context.clone()
    }

    /// The statement's relation graph: every relation it names, where each one sits, and every
    /// relationship between them that the statement wrote down.
    ///
    /// [`Self::objects`] folds the same parse into a set of names; this keeps the multiplicity,
    /// the position, the nesting depth and the edges. See [`StatementGraph`].
    pub fn relation_graph(&self) -> StatementGraph {
        StatementGraph::of(&self.statement)
    }

    /// returns the relations this statement names, deduplicated and sorted
    ///
    /// A set, so multiplicity, position, nesting depth and the relationships between the
    /// relations are not carried. [`Self::relation_graph`] is the same parse with them.
    pub fn objects(&self) -> Vec<EntrySqlStatementObject> {
        let mut visited = BTreeSet::new();

        let _ = visit_relations(&self.statement, |relation| {
            let ident = &relation.0;

            let _ = visited.insert(if ident.len() == 2 {
                EntrySqlStatementObject {
                    schema_name: Some(Bytes::from(ident[0].to_string())),
                    object_name: Bytes::from(ident[1].to_string()),
                }
            } else {
                EntrySqlStatementObject {
                    schema_name: None,
                    object_name: ident.last().unwrap().to_string().to_owned().into(),
                }
            });

            ControlFlow::<()>::Continue(())
        });
        visited.into_iter().collect()
    }

    /// returns the MySQL-facing kind of this statement
    pub fn sql_type(&self) -> EntrySqlType {
        match self.statement {
            // MySQL 8.0 admits `WITH c AS (…) INSERT/UPDATE/DELETE …`, which parses as a
            // `Query` whose body is the write. Reading the outer node alone would type all
            // three as reads.
            Statement::Query(ref q) => match q.body.as_ref() {
                SetExpr::Insert(_) => EntrySqlType::Insert,
                SetExpr::Update(_) => EntrySqlType::Update,
                SetExpr::Delete(_) => EntrySqlType::Delete,
                _ => EntrySqlType::Query,
            },
            Statement::Insert { .. } => EntrySqlType::Insert,
            Statement::Update { .. } => EntrySqlType::Update,
            Statement::Delete { .. } => EntrySqlType::Delete,
            Statement::CreateTable { .. } => EntrySqlType::CreateTable,
            Statement::CreateIndex { .. } => EntrySqlType::CreateIndex,
            Statement::CreateView { .. } => EntrySqlType::CreateView,
            Statement::AlterTable { .. } => EntrySqlType::AlterTable,
            // One arm per object type, because the label is what a consumer matches on and
            // `DROP TABLE` asserts the object a `DROP VIEW` or a `DROP DATABASE` is not.
            Statement::Drop {
                object_type: ObjectType::View,
                ..
            } => EntrySqlType::DropView,
            Statement::Drop {
                object_type: ObjectType::Database | ObjectType::Schema,
                ..
            } => EntrySqlType::DropDatabase,
            Statement::Drop { .. } => EntrySqlType::Drop,
            Statement::DropFunction { .. } => EntrySqlType::DropFunction,
            Statement::Set { .. } => EntrySqlType::Set,
            Statement::ShowVariable { .. } => EntrySqlType::ShowVariable,
            Statement::ShowVariables { .. } => EntrySqlType::ShowVariables,
            Statement::ShowCreate { .. } => EntrySqlType::ShowCreate,
            Statement::ShowColumns { .. } => EntrySqlType::ShowColumns,
            Statement::ShowTables { .. } => EntrySqlType::ShowTables,
            Statement::ShowCollation { .. } => EntrySqlType::ShowCollation,
            Statement::Use { .. } => EntrySqlType::Use,
            Statement::StartTransaction { .. } => EntrySqlType::StartTransaction,
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
            // The statement that releases a table lock, kept apart from the one that takes it:
            // `Lock_time` is the wait for that lock, so a consumer counting lock-takers must not
            // meet the two under one name.
            Statement::UnlockTables => EntrySqlType::UnlockTables,
            Statement::Flush { .. } => EntrySqlType::Flush,
            // `sqlparser` has hundreds of statement forms and this enum cannot have one arm
            // each. An arm is owed where the relation graph already gives the statement a role:
            // these three take a truncate target, a drop and a create target, and an analyze
            // target there. `CALL`, `EXECUTE` and `DEALLOCATE` parse and take no role from the
            // walk, so `Unknown` is what this enum says about them.
            Statement::Truncate { .. } => EntrySqlType::Truncate,
            Statement::RenameTable { .. } => EntrySqlType::RenameTable,
            Statement::Analyze { .. } => EntrySqlType::Analyze,
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

    /// returns the relation graph of this statement, where it has one
    ///
    /// `None` exactly where [`Self::objects`] is `None`, and for the same reason: an admin
    /// command and an unparseable statement have no AST to walk. The two remain distinct in the
    /// enum itself; this accessor says only that neither has a graph.
    pub fn relation_graph(&self) -> Option<StatementGraph> {
        match self {
            Self::SqlStatement(s) => Some(s.relation_graph()),
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
    /// returns the key/value pairs parsed from the statement's preceding comment
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
    /// DROP TABLE
    Drop,
    /// DROP VIEW
    DropView,
    /// DROP DATABASE / DROP SCHEMA
    DropDatabase,
    /// DROP FUNCTION
    DropFunction,
    /// SET
    Set,
    /// `SHOW <anything this enum has no arm for>`. Upstream's `Statement::ShowVariable` is a
    /// catch-all rather than a variable: `SHOW WARNINGS`, `SHOW ENGINE INNODB STATUS`,
    /// `SHOW GRANTS` and `SHOW CHARACTER SET` all land here, which is why it displays as `SHOW`
    /// and not as `SHOW VARIABLE`.
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
    /// TRUNCATE TABLE
    Truncate,
    /// RENAME TABLE
    RenameTable,
    /// ANALYZE TABLE
    Analyze,
    /// The statement parsed and this enum has no MySQL name for it. Not an absence: `Display`
    /// spells it `UNKNOWN`, so a consumer can tell it from a line that had no statement at all.
    ///
    /// Two kinds land here. One is ordinary MySQL this enum has no arm for — `CALL`, `EXECUTE`,
    /// `DEALLOCATE` — which the relation graph gives no role either. The other is text
    /// `sqlparser` accepts and MySQL cannot write, such as `ALTER INDEX`; this crate reads MySQL
    /// slow logs, so naming those would make the vocabulary a union of every dialect
    /// `sqlparser` knows and put cases that cannot occur in front of every consumer.
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
            Self::Drop => "DROP TABLE",
            Self::DropView => "DROP VIEW",
            Self::DropDatabase => "DROP DATABASE",
            Self::DropFunction => "DROP FUNCTION",
            Self::Set => "SET",
            Self::ShowVariable => "SHOW",
            Self::ShowVariables => "SHOW VARIABLES",
            Self::ShowCreate => "SHOW CREATE TABLE",
            Self::ShowColumns => "SHOW COLUMNS",
            Self::ShowTables => "SHOW TABLES",
            Self::ShowCollation => "SHOW COLLATION",
            Self::Use => "USE",
            Self::StartTransaction => "BEGIN TRANSACTION",
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
            Self::Truncate => "TRUNCATE TABLE",
            Self::RenameTable => "RENAME TABLE",
            Self::Analyze => "ANALYZE TABLE",
            // A name and never the word `NULL`: a statement this enum has no arm for and a line
            // that carried no statement are different facts, and a consumer writing this label
            // into a nullable column has to be able to tell them apart.
            Self::Unknown => "UNKNOWN",
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
    /// The reader's rendering: for a parsed statement this is the AST rendered back to text,
    /// for an admin command the command word, for an unparseable statement the log's bytes.
    ///
    /// Three different things, and [`Self::statement`]'s arm is what says which.
    pub sql: Bytes,
    /// The author's own bytes, exactly as the log carried them, `;` included.
    ///
    /// `None` only for an administrator command, where a different parser consumed the line and
    /// its framing -- and there `sql` is already the log's own bytes, so nothing is lost.
    ///
    /// This is the only record of keyword case, line layout, in-statement comments and the
    /// author's unmasked literals: `sql` above discards all of it for the statements that
    /// parsed.
    pub sql_raw: Option<Bytes>,
    /// Every literal the author wrote, in traversal order, whether or not masking is on.
    pub literals: Vec<EntryLiteral>,
    /// The database the log said was current, where it said so.
    ///
    /// `USE` is sticky per connection and MySQL writes it only when the database changes, so
    /// this is `None` on every entry that did not itself carry one. Carrying it forward along a
    /// thread is a reader's inference and belongs to whoever draws it.
    pub use_database: Option<Bytes>,
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
#[derive(Clone, Debug, PartialEq)]
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
        self.log_time.clone()
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

#[cfg(test)]
mod every_sql_type_arm {
    use super::*;
    use sqlparser::dialect::MySqlDialect;
    use sqlparser::parser::Parser;
    use std::collections::BTreeSet;

    fn typed(sql: &str) -> EntrySqlType {
        let mut s =
            Parser::parse_sql(&MySqlDialect {}, sql).unwrap_or_else(|e| panic!("{sql}: {e}"));
        assert_eq!(s.len(), 1, "{sql}");
        EntrySqlStatement::from(s.remove(0)).sql_type()
    }

    /// ⭐⭐⭐ EVERY ARM OF [`EntrySqlType`], AND THE REGIME THAT CAN REACH IT.
    ///
    /// Sweeping this enum the way `JoinOp` was swept found **five defects**, every one of them
    /// in an arm no corpus had ever produced:
    ///
    /// | | |
    /// |---|---|
    /// | ⛔ `UNLOCK TABLES` typed as `LockTables` | the arm was dead, and 16 of the shipped log's 32 "LOCK TABLES" rows release a lock rather than take one |
    /// | ⛔ `Unknown` displayed as `"NULL"` | four characters, in a nullable column documented as meaning "not SQL" |
    /// | ⛔ `TRUNCATE`, `RENAME TABLE`, `ANALYZE TABLE` had no arm | `graph.rs` walks all three and gives them roles — one record disagreeing with itself |
    /// | ⛔ `DROP VIEW` and `DROP DATABASE` displayed as `"DROP TABLE"` | the label asserted the one object type it was not |
    /// | ⛔ `SetTransaction` was unreachable | nothing in the classifier produced it; every spelling of `SET TRANSACTION …` parses as `Statement::Set` |
    ///
    /// ⚠️ And `ShowVariable` is upstream's catch-all rather than a variable, so it displays as
    /// `SHOW`.
    #[test]
    fn every_arm_that_a_mysql_statement_reaches_has_one() {
        // ⭐ Ordinary MySQL. Each of these is text the server that wrote the log could have run.
        let mysql: &[(&str, EntrySqlType)] = &[
            ("SELECT 1 FROM t", EntrySqlType::Query),
            ("INSERT INTO t VALUES (1)", EntrySqlType::Insert),
            ("UPDATE t SET a = 1", EntrySqlType::Update),
            ("DELETE FROM t", EntrySqlType::Delete),
            // A `WITH` in front of a write parses as a `Query` whose body is the write, so the
            // outer node alone types all three as reads.
            (
                "WITH c AS (SELECT 1 AS i) INSERT INTO t SELECT i FROM c",
                EntrySqlType::Insert,
            ),
            (
                "WITH c AS (SELECT 1 AS i) UPDATE t SET a = 1",
                EntrySqlType::Update,
            ),
            (
                "WITH c AS (SELECT 1 AS i) DELETE FROM t",
                EntrySqlType::Delete,
            ),
            ("CREATE TABLE t (a INT)", EntrySqlType::CreateTable),
            ("CREATE INDEX i ON t (a)", EntrySqlType::CreateIndex),
            ("CREATE VIEW v AS SELECT 1 FROM t", EntrySqlType::CreateView),
            ("ALTER TABLE t ADD COLUMN b INT", EntrySqlType::AlterTable),
            ("DROP TABLE t", EntrySqlType::Drop),
            ("DROP VIEW v", EntrySqlType::DropView),
            ("DROP DATABASE d", EntrySqlType::DropDatabase),
            ("DROP SCHEMA d", EntrySqlType::DropDatabase),
            ("DROP FUNCTION f", EntrySqlType::DropFunction),
            ("SET autocommit = 0", EntrySqlType::Set),
            // ⚠️ Every `SET TRANSACTION` spelling lands on `Set`, which is why `connection.rs`
            // reads the isolation level off the author's bytes rather than off this enum.
            (
                "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
                EntrySqlType::Set,
            ),
            (
                "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
                EntrySqlType::Set,
            ),
            ("SHOW WARNINGS", EntrySqlType::ShowVariable),
            ("SHOW ENGINE INNODB STATUS", EntrySqlType::ShowVariable),
            ("SHOW VARIABLES LIKE 'long%'", EntrySqlType::ShowVariables),
            ("SHOW CREATE TABLE t", EntrySqlType::ShowCreate),
            ("SHOW COLUMNS FROM t", EntrySqlType::ShowColumns),
            ("SHOW TABLES FROM d", EntrySqlType::ShowTables),
            ("SHOW COLLATION", EntrySqlType::ShowCollation),
            ("USE d", EntrySqlType::Use),
            ("START TRANSACTION", EntrySqlType::StartTransaction),
            ("BEGIN", EntrySqlType::StartTransaction),
            ("COMMIT", EntrySqlType::Commit),
            ("ROLLBACK", EntrySqlType::Rollback),
            ("CREATE SCHEMA d", EntrySqlType::CreateSchema),
            ("CREATE DATABASE d", EntrySqlType::CreateDatabase),
            ("GRANT SELECT ON d.* TO 'u'@'h'", EntrySqlType::Grant),
            ("REVOKE SELECT ON d.* FROM 'u'@'h'", EntrySqlType::Revoke),
            ("KILL 12345", EntrySqlType::Kill),
            ("EXPLAIN t", EntrySqlType::ExplainTable),
            ("DESCRIBE t", EntrySqlType::ExplainTable),
            ("EXPLAIN SELECT 1 FROM t", EntrySqlType::Explain),
            ("SAVEPOINT sp1", EntrySqlType::Savepoint),
            ("LOCK TABLES t WRITE", EntrySqlType::LockTables),
            ("UNLOCK TABLES", EntrySqlType::UnlockTables),
            ("FLUSH TABLES", EntrySqlType::Flush),
            ("TRUNCATE TABLE t", EntrySqlType::Truncate),
            ("RENAME TABLE a TO b", EntrySqlType::RenameTable),
            ("ANALYZE TABLE t", EntrySqlType::Analyze),
            // ⭐ `Unknown` is a REAL arm and this is what it means: parsed, and this enum has no
            // name for it. The rule for when an arm is owed instead is that another artifact in
            // the record already says something specific — `graph.rs` gives these no role.
            ("CALL myproc(1)", EntrySqlType::Unknown),
            ("EXECUTE s", EntrySqlType::Unknown),
            ("DEALLOCATE PREPARE s", EntrySqlType::Unknown),
            ("SHOW STATUS", EntrySqlType::Unknown),
        ];
        let mut seen: BTreeSet<String> = Default::default();
        for (sql, want) in mysql {
            assert_eq!(typed(sql), *want, "{sql}");
            seen.insert(format!("{want:?}"));
        }

        // ⛔ AND TEXT MYSQL CANNOT WRITE LANDS ON `Unknown` TOO. MySQL has no `ALTER INDEX`
        // statement at all; `sqlparser` parses one because its parser is largely shared across
        // dialects. It had its own arm, which made the vocabulary a union of every dialect
        // `sqlparser` knows — **this crate reads MySQL slow logs**, so the case that cannot
        // occur does not get a name of its own.
        assert_eq!(
            typed("ALTER INDEX idx RENAME TO idx2"),
            EntrySqlType::Unknown
        );

        // ⛔ THE GUARD. Written out rather than derived, because the enum cannot be iterated —
        // so a new arm without a case has to fail here. This sweep removed two: `SetTransaction`,
        // which nothing in the classifier produced, and `AlterIndex`, which no MySQL server can
        // write.
        assert_eq!(
            seen.len(),
            38,
            "every EntrySqlType arm needs a statement that reaches it; reached {seen:?}"
        );
    }

    /// ⛔⛔ THE LABEL IS WHAT A READER SEES, AND FOUR OF THEM ASSERTED SOMETHING FALSE.
    ///
    /// `Display` is not cosmetic here: `parquet.rs` writes `sql_type().to_string()` straight into
    /// the column, so each of these strings IS the filed value.
    #[test]
    fn no_label_asserts_something_the_statement_did_not_say() {
        // ⛔ The one that mattered most: a four-character string spelling itself as the absence
        // marker, in a nullable column whose documentation said NULL means "not SQL".
        assert_eq!(EntrySqlType::Unknown.to_string(), "UNKNOWN");
        assert_ne!(EntrySqlType::Unknown.to_string(), "NULL");

        // ⛔ Three labels that named the wrong object or the wrong direction.
        assert_eq!(EntrySqlType::UnlockTables.to_string(), "UNLOCK TABLES");
        assert_eq!(EntrySqlType::DropView.to_string(), "DROP VIEW");
        assert_eq!(EntrySqlType::DropDatabase.to_string(), "DROP DATABASE");

        // ⚠️ And the catch-all, which is not a variable.
        assert_eq!(EntrySqlType::ShowVariable.to_string(), "SHOW");

        // ⭐ Every label distinct, so no two arms collapse in the parquet the way `Drop` and
        // `DropView` did and the way `LockTables` and `UnlockTables` did.
        let labels: Vec<String> = [
            EntrySqlType::Query,
            EntrySqlType::Insert,
            EntrySqlType::Update,
            EntrySqlType::Delete,
            EntrySqlType::CreateTable,
            EntrySqlType::CreateIndex,
            EntrySqlType::CreateView,
            EntrySqlType::AlterTable,
            EntrySqlType::Drop,
            EntrySqlType::DropView,
            EntrySqlType::DropDatabase,
            EntrySqlType::DropFunction,
            EntrySqlType::Set,
            EntrySqlType::ShowVariable,
            EntrySqlType::ShowVariables,
            EntrySqlType::ShowCreate,
            EntrySqlType::ShowColumns,
            EntrySqlType::ShowTables,
            EntrySqlType::ShowCollation,
            EntrySqlType::Use,
            EntrySqlType::StartTransaction,
            EntrySqlType::Commit,
            EntrySqlType::Rollback,
            EntrySqlType::CreateSchema,
            EntrySqlType::CreateDatabase,
            EntrySqlType::Grant,
            EntrySqlType::Revoke,
            EntrySqlType::Kill,
            EntrySqlType::ExplainTable,
            EntrySqlType::Explain,
            EntrySqlType::Savepoint,
            EntrySqlType::LockTables,
            EntrySqlType::UnlockTables,
            EntrySqlType::Flush,
            EntrySqlType::Truncate,
            EntrySqlType::RenameTable,
            EntrySqlType::Analyze,
            EntrySqlType::Unknown,
        ]
        .iter()
        .map(|t| t.to_string())
        .collect();
        assert_eq!(labels.len(), 38);
        let distinct: BTreeSet<&String> = labels.iter().collect();
        assert_eq!(distinct.len(), 38, "two arms share a label: {labels:?}");
    }
}
