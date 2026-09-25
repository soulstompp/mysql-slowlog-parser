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

pub use crate::codec::{CodecError, DecodeStage, EntryCodec, FileScope};

/// Declares a public enum's published vocabulary: the string each arm reaches an artifact as.
///
/// The arms are written **once**, so `name()`, `NAMES` and `all()` cannot disagree about which arms
/// exist or what they are called. A consumer that spelled the strings itself would be a second
/// authority on what they mean, and nothing would make the two agree — which is why they are
/// published from the crate that owns the arms.
///
/// The generated `name()` is an **exhaustive** match, deliberately. These enums are
/// `#[non_exhaustive]`, which restricts a consumer and not this crate, so adding an arm breaks the
/// build *here*, beside the arm, where the decision about what to call it belongs. A consumer never
/// matches at all and so cannot acquire an answer nobody chose.
macro_rules! vocabulary {
    // Fieldless arms, so each one is a value: `all()` lets a consumer close a law over the whole
    // vocabulary without transcribing it.
    ($enum:ident { $($arm:ident => $name:literal,)+ }) => {
        impl $enum {
            /// The published string for this arm — the value that reaches an artifact column.
            pub fn name(&self) -> &'static str {
                match self { $(Self::$arm => $name,)+ }
            }
            /// Every published string, in declaration order.
            pub const NAMES: &'static [&'static str] = &[$($name,)+];
            /// Every arm. Derived from the same list as [`Self::name`].
            pub fn all() -> impl Iterator<Item = Self> + Clone {
                [$(Self::$arm,)+].into_iter()
            }
        }
    };
    // Arms carrying a payload. No `all()`: an arm is not a value on its own, so what a consumer can
    // close a law over is `NAMES`, which is what the artifact carries anyway.
    ($enum:ident { $($arm:pat => $name:literal,)+ }) => {
        impl $enum {
            /// The published string for this arm — the value that reaches an artifact column.
            pub fn name(&self) -> &'static str {
                match self { $($arm => $name,)+ }
            }
            /// Every published string, in declaration order.
            pub const NAMES: &'static [&'static str] = &[$($name,)+];
        }
    };
}

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

/// How a statement's values are rendered in [`EntrySqlAttributes::sql()`].
///
/// Masking changes the rendering and nothing else: [`EntrySqlAttributes::sql_raw`] and
/// [`EntrySqlAttributes::literals`] hold what the author wrote under either setting.
///
/// A parsed statement is masked in its tree. A statement the grammar refuses is masked token by
/// token over the author's text, every other byte kept, so a type length such as `CHAR(60)` is
/// masked too. An administrator command carries no values and is rendered as written.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[non_exhaustive]
pub enum EntryMasking {
    /// Every literal is rendered as a `?` placeholder, so two calls of one query that differ only
    /// in their values render to the same text. A negative number is one literal. A value inside
    /// an optimizer hint (`/*+ ... */`) of a parsed statement is not masked, because the grammar
    /// hands the hint over as text.
    PlaceHolder,
    /// Literals are rendered as written.
    #[default]
    None,
}

vocabulary!(EntryMasking {
    PlaceHolder => "placeholder",
    None => "none",
});

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
