//! A streaming parser for MySQL slow query logs.
//!
//! [`EntryCodec`] is a [`Decoder`](tokio_util::codec::Decoder) that turns the bytes of a slow log
//! into [`Entry`] values, so anything [`FramedRead`](tokio_util::codec::FramedRead) can wrap can
//! be read without holding the log in memory. Each entry carries the call, the session, the stats
//! and the statement. A statement the SQL grammar accepts also carries its [`sqlparser`] AST and a
//! [`StatementGraph`] of the relations it names.
//!
//! # Example
//!
//! ```rust
//! use futures::StreamExt;
//! use mysql_slowlog_parser::EntryCodec;
//! use tokio::fs::File;
//! use tokio_util::codec::FramedRead;
//!
//! #[tokio::main]
//! async fn main() {
//!     let file = File::open("assets/slow-test-queries.log").await.unwrap();
//!     let mut entries = FramedRead::new(file, EntryCodec::default());
//!
//!     let mut count = 0;
//!     while let Some(entry) = entries.next().await {
//!         let entry = entry.unwrap();
//!         println!("{:.6}s {}", entry.query_time(), entry.sql_attributes.sql());
//!         count += 1;
//!     }
//!
//!     println!("parsed {count} entries");
//! }
//! ```

#![deny(
    missing_copy_implementations,
    trivial_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    missing_docs
)]

use std::collections::HashMap;
use std::default::Default;
use std::fmt::{Debug, Formatter};

pub use crate::parser::{
    EntryAdminCommand, EntryLiteral, HeaderLines, LiteralColumn, LiteralKind, SessionLine,
    SqlStatementContext, StatsLine, TimeLine, carries_a_value, rewrite_literals,
};

use bytes::Bytes;

pub use crate::codec::{CodecError, EntryCodec, EntryError, FileScope};

mod codec;
mod graph;
mod parser;
mod types;

/// The SQL grammar whose AST [`EntrySqlStatement::statement`] holds, re-exported so a caller
/// names the version this crate was built against.
pub use sqlparser;
/// The date and time types [`EntryCall`] exposes, re-exported for the same reason.
pub use winnow_datetime;

pub use graph::{
    Clause, Connective, ConstraintKind, Edge, GraphMeasures, IndexHint, IndexHintKind,
    IndexHintScope, JoinOp, LockStrength, LockWait, OptimizerHintText, Partition, PathStep,
    Predicate, PredicateOp, RelationOccurrence, RelationRole, RhsKind, Scope, ScopeKind,
    SetOperator, Side, SortDirections, Stages, StatementGraph,
};

pub use types::{
    Entry, EntryCall, EntrySession, EntrySqlAttributes, EntrySqlStatement, EntrySqlStatementObject,
    EntrySqlType, EntryStatement, EntryStats,
};

/// How a parsed statement's values are rendered in [`EntrySqlAttributes::sql()`].
///
/// Masking changes the rendering and nothing else: [`EntrySqlAttributes::sql_raw`] and
/// [`EntrySqlAttributes::literals`] hold what the author wrote under either setting.
///
/// Only a statement the grammar parses is masked. A refused statement is carried as the log's
/// own bytes, values included, and so is an administrator command.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[non_exhaustive]
pub enum EntryMasking {
    /// Every recorded literal is rendered as a `?` placeholder, so two calls of one query that
    /// differ only in their values render to the same text. A bit literal (`b'1'`) is not
    /// recorded and is not masked.
    PlaceHolder,
    /// Literals are rendered as written.
    #[default]
    None,
}

/// Configuration for [`EntryCodec::new`].
#[derive(Copy, Clone, Default)]
pub struct EntryCodecConfig {
    /// How values are rendered in [`EntrySqlAttributes::sql()`].
    pub masking: EntryMasking,
    /// Maps the key/value pairs of the comment preceding a statement to its
    /// [`SqlStatementContext`]. `None` keeps every pair under the key the comment used; a
    /// function can filter or rename pairs, or return `None` to drop the context.
    #[allow(clippy::type_complexity)]
    pub map_comment_context: Option<fn(HashMap<Bytes, Bytes>) -> Option<SqlStatementContext>>,
}

impl Debug for EntryCodecConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryCodecConfig")
            .field("masking", &self.masking)
            .field(
                "map_comment_context",
                &self.map_comment_context.map(|_| "fn"),
            )
            .finish()
    }
}
