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
use thiserror::Error;

pub use crate::parser::{EntryAdminCommand, SessionLine, SqlStatementContext, StatsLine, TimeLine};

use bytes::Bytes;

pub use crate::codec::{CodecError, EntryCodec, EntryError};

mod codec;
mod parser;
mod types;

pub use types::{
    Entry, EntryCall, EntryContext, EntrySession, EntrySqlAttributes, EntrySqlStatementObject,
    EntrySqlType, EntryStatement, EntryStats,
};

/// Error covering problems reading or parsing a log
#[derive(Error, Debug)]
pub enum ReadError {
    /// problem found where a Time:... line is expected
    #[error("invalid time line: {0}")]
    InvalidTimeLine(String),
    /// problem found where a User:... line is expected
    #[error("invalid user line: {0}")]
    InvalidUserLine(String),
    /// problem found where a Query_time:... line is expected
    #[error("invalid stats line: {0}")]
    InvalidStatsLine(String),
    /// problem found at end of file with an incomplete SQL statement
    #[error("invalid entry with invalid sql starting at end of file")]
    IncompleteSql,
    /// problem found at end of file somewhere in the middle of an entry
    #[error("Invalid log format or format contains no entries")]
    IncompleteLog,
}

/// types of masking to apply when parsing SQL statements
/// * PlaceHolder - mask all sql values with a '?' placeholder
/// * None - leave all values in place
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EntryMasking {
    /// A placeholder `?` is used when a binding is found in a query
    PlaceHolder,
    /// No placeholder mask
    None,
}

impl Default for EntryMasking {
    fn default() -> Self {
        Self::None
    }
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

/// errors that occur when building a Reader
#[derive(Error, Clone, Copy, Debug)]
pub enum ReaderBuildError {
    /// missing reader value
    #[error("reader must be set to build Reader")]
    MissingReader,
}
