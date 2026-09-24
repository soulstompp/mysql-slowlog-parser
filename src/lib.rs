//! # parse-mysql-slowlog streams a slow query and returns a stream of entries from slow logs
//!   from your `FramedReader` tokio input of choice.
//!
//!## Example:
//!
//!```rust
//! use futures::StreamExt;
//! use mysql_slowlog_parser::{CodecError, Entry, EntryCodec};
//! use std::ops::AddAssign;
//! use std::time::Instant;
//! use tokio::fs::File;
//! use tokio_util::codec::FramedRead;
//!
//! #[tokio::main]
//! async fn main() {
//! let start = Instant::now();
//!
//! let fr = FramedRead::with_capacity(
//!     File::open("assets/slow-test-queries.log")
//!     .await
//!     .unwrap(),
//!     EntryCodec::default(),
//!        400000,
//!);
//!
//!    let mut i = 0;
//!
//!    let future = fr.for_each(|re: Result<Entry, CodecError>| async move {
//!        let _ = re.unwrap();
//!
//!        i.add_assign(1);
//!    });
//!
//!    future.await;
//!    println!("parsed {} entries in: {}", i, start.elapsed().as_secs_f64());
//!}
//! ```

#![deny(
    missing_copy_implementations,
    trivial_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    missing_docs
)]

extern crate core;

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

/// types of masking to apply when parsing SQL statements
/// * PlaceHolder - mask all sql values with a '?' placeholder
/// * None - leave all values in place
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum EntryMasking {
    /// A placeholder `?` is used when a binding is found in a query
    PlaceHolder,
    /// No placeholder mask
    #[default]
    None,
}

/// Struct to pass along configuration values to codec
#[derive(Copy, Clone, Default)]
pub struct EntryCodecConfig {
    /// type of masking to use when parsing SQL
    pub masking: EntryMasking,
    /// mapping function in order to find specific key entries
    pub map_comment_context: Option<fn(HashMap<Bytes, Bytes>) -> Option<SqlStatementContext>>,
}

impl Debug for EntryCodecConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.masking)?;
        write!(f, "map_comment_context: fn")
    }
}
