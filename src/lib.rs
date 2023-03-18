//! # Parse MySQL SlowLog
//!
//! A pull parser library for reading MySQL's slow query logs.
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
        Option<Box<dyn Fn(HashMap<Bytes, Bytes>) -> Option<SqlStatementContext>>>,
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
