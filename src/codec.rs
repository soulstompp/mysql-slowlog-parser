//! The framing reader: bytes of a slow log in, one [`Entry`] at a time out.
//!
//! What it reads: the file's header block, then, per entry, the `# Time:`, `# User@Host:` and
//! `# Query_time:` lines, an optional `USE <db>;`, the `SET timestamp=…;` line, and finally
//! either an administrator command or the statement's own bytes. Each of those is a parser in
//! [`crate::parser`]; this module is the state machine that orders them and the buffer
//! arithmetic that lets a partial read resume.
//!
//! What it refuses: a line its stage cannot read, which is returned as
//! [`CodecError::Malformed`] rather than skipped; and input that ends inside an entry, which
//! [`Decoder::decode_eof`] reports as [`CodecError::Truncated`] so a caller can tell a truncated
//! log from a complete one.
//!
//! What it declines to interpret: the statement text, which is handed to `sqlparser` and filed
//! as [`EntryStatement::InvalidStatement`] where that refuses it or reads other than exactly one
//! statement from it; the header's version string,
//! which is carried as the server spelled it; and a `USE` database, which is filed on the entry
//! that wrote it and never carried forward to the next entry on the same connection.
//!
//! Two scopes, and the distinction is load-bearing: [`EntryContext`] is cleared when an entry
//! completes, [`FileScope`] is not.

use crate::parser::{
    HeaderLines, Stream, admin_command, details_comment, entry_user, log_header, parse_entry_stats,
    parse_entry_time, parse_sql, sql_lines, start_timestamp_command, use_database,
};
use crate::types::EntryStatement::SqlStatement;
use crate::types::{Entry, EntryCall, EntrySqlAttributes, EntrySqlStatement, EntryStatement};
use crate::{EntryCodecConfig, SessionLine, SqlStatementContext, StatsLine};
use bytes::{Buf, Bytes, BytesMut};
use log::debug;
use std::borrow::Cow;
use std::default::Default;
use std::fmt::{Display, Formatter, Write as _};
use thiserror::Error;
use tokio::io;
use tokio_util::codec::Decoder;
use winnow::ascii::multispace0;
use winnow::combinator::opt;
use winnow::error::{ContextError, ErrMode};
use winnow::stream::{Stream as _, StreamIsPartial};
use winnow::{ModalResult, Parser};
use winnow_datetime::DateTime;

/// The most bytes of a line a [`CodecError`] carries.
const EXCERPT_MAX: usize = 200;

/// Errors for problems when reading frames from the source.
///
/// The decoder does not skip what it cannot read: decoding again from the same state reports
/// the same error, and `FramedRead` ends the stream after the first one.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecError {
    /// An error from the reader.
    #[error("I/O error: {0}")]
    IO(#[from] io::Error),
    /// A line the stage the decoder had reached cannot read.
    #[error("cannot read the {stage} of entry {entry}: {line:?}")]
    Malformed {
        /// what the decoder was reading
        stage: DecodeStage,
        /// the entry's position in the input, counting from zero, which is how many entries were
        /// decoded before it
        entry: usize,
        /// the first line of what the stage refused, lossily decoded and cut to at most 200
        /// bytes
        line: String,
    },
    /// Input that ends inside an entry: MySQL ends every entry with its statement and a `;`.
    #[error("input ends inside the {stage} of entry {entry}: {line:?}")]
    Truncated {
        /// what the decoder was reading when the input ended
        stage: DecodeStage,
        /// the entry's position in the input, counting from zero
        entry: usize,
        /// the first line of what was left, lossily decoded and cut to at most 200 bytes; empty
        /// where nothing was
        line: String,
    },
}

/// The part of an entry the decoder is reading, as a [`CodecError`] reports it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum DecodeStage {
    /// a header block, which MySQL writes each time it opens the log
    #[default]
    Header,
    /// the `# Time:` line
    Time,
    /// the `# User@Host:` line
    Session,
    /// the `# Query_time:` line
    Stats,
    /// the `use <db>;` line
    UseDatabase,
    /// the `SET timestamp=…;` line
    SetTimestamp,
    /// the statement or the administrator command
    Statement,
}

impl Display for DecodeStage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            DecodeStage::Header => "header block",
            DecodeStage::Time => "time line",
            DecodeStage::Session => "session line",
            DecodeStage::Stats => "stats line",
            DecodeStage::UseDatabase => "use line",
            DecodeStage::SetTimestamp => "SET timestamp line",
            DecodeStage::Statement => "statement",
        };
        write!(f, "{}", out)
    }
}

/// Why a stage stopped without finishing.
enum Halt {
    /// the buffer ends before the stage does
    Incomplete,
    /// the stage's grammar refused what is there
    Refused,
}

impl From<ErrMode<ContextError>> for Halt {
    fn from(e: ErrMode<ContextError>) -> Self {
        match e {
            ErrMode::Incomplete(_) => Halt::Incomplete,
            ErrMode::Backtrack(_) | ErrMode::Cut(_) => Halt::Refused,
        }
    }
}

/// The half-read entry. Everything here is cleared when an entry completes, which is the
/// contract that makes the two-scope model work; [`FileScope`] is what survives.
///
/// Nothing that is a fact about the *file* may be held here, because completing an entry destroys
/// it. The clearing is [`EntryContext::complete`]'s `mem::take`, so a field taken out of this
/// struct is moved rather than copied.
#[derive(Debug, Default)]
struct EntryContext {
    expects: DecodeStage,
    time: Option<DateTime>,
    user: Option<SessionLine>,
    stats: Option<StatsLine>,
    set_timestamp: Option<u32>,
    use_database: Option<Bytes>,
    attributes: Option<EntrySqlAttributes>,
}

impl EntryContext {
    /// Takes the half-read entry's fields and builds the [`Entry`], or `None` where one is unset.
    ///
    /// `mem::take` is also the reset: the fields are moved out and the default is left behind, so
    /// nothing is copied on the way. `attributes` carries a whole `sqlparser::ast::Statement`,
    /// which a clone would deep-copy node by node.
    ///
    /// The state machine fills every field before the statement stage is reached, so `None` is
    /// unreachable; the caller reports it as the statement stage's refusal rather than panicking.
    fn complete(&mut self) -> Option<Entry> {
        let ctx = std::mem::take(self);

        Some(Entry {
            call: EntryCall::new(ctx.time?, ctx.set_timestamp?),
            session: ctx.user?.into(),
            stats: ctx.stats?.into(),
            sql_attributes: ctx.attributes?,
        })
    }
}

/// Everything a codec holds that is a fact about the *file* rather than about one entry: the
/// header block, how many header blocks have been seen, and how many entries have been decoded.
///
/// This is the state to hand to a codec reading a later shard of the same log. Only the first
/// shard holds the header, so without it a second shard states no server version — and a claim
/// about MySQL's behaviour only means something inside the regime a version names.
///
/// It is `O(1)`: one header block and two counters, whatever the file's size.
/// [`EntryCodec::file_scope`] produces one and [`EntryCodec::resume`] takes one, so splitting a
/// log and reading a log in two buffers are the same operation.
///
/// Produced and never authored: the fields are private, so anything but the empty default comes
/// from a codec that read the prefix.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileScope {
    headers: Option<HeaderLines>,
    headers_seen: usize,
    processed: usize,
}

impl FileScope {
    /// The header block the file opened with, or `None` where it had none.
    pub fn headers(&self) -> Option<&HeaderLines> {
        self.headers.as_ref()
    }

    /// How many header blocks have been seen. See [`EntryCodec::header_count`].
    pub fn header_count(&self) -> usize {
        self.headers_seen
    }

    /// Entries decoded so far. A count, which is what a caller adds to a later shard's own
    /// positions to recover each entry's position in the whole log.
    pub fn processed(&self) -> usize {
        self.processed
    }
}

/// The [`Decoder`] for a MySQL slow log: bytes in, one [`Entry`] per log entry out.
///
/// It reads the entry format MySQL 5.7 and later write by default, with an ISO 8601 `# Time:`
/// line on every entry. A line it cannot read is an error rather than being skipped; see
/// [`CodecError`].
#[derive(Debug, Default)]
pub struct EntryCodec {
    /// File-scoped state, in one place because it is one scope. See [`FileScope`].
    file: FileScope,
    context: EntryContext,
    config: EntryCodecConfig,
}

impl EntryCodec {
    /// The state this codec carries that is not one entry's: see [`FileScope`].
    ///
    /// Valid at any point; a caller holding a `FramedRead` reaches it through `decoder()`. It
    /// does not include the half-read entry, which is not a fact about the file — a shard
    /// boundary is an entry boundary by construction, and a cut mid-entry is not supported.
    pub fn file_scope(&self) -> &FileScope {
        &self.file
    }

    /// Resume from the state a previous shard left.
    ///
    /// A shard of a log carries no header of its own; this is how the server version reaches it.
    /// The state must have been produced by reading the prefix — see [`FileScope`].
    pub fn resume(c: EntryCodecConfig, file: FileScope) -> Self {
        Self {
            file,
            config: c,
            ..Default::default()
        }
    }
    /// The header lines the file opened with, or `None` where it had none.
    ///
    /// Valid once the first entry has been decoded; a caller holding a `FramedRead` reaches it
    /// through `decoder()`. `None` means the file states no server, and never "the default
    /// server": a rotated or concatenated slow log begins mid-stream and names none.
    pub fn headers(&self) -> Option<&HeaderLines> {
        self.file.headers.as_ref()
    }

    /// How many header blocks the file carried.
    ///
    /// MySQL writes one each time it opens the log, so more than one means a restart, a reopen or
    /// a concatenation, and the first header's server version need not hold for the entries after
    /// the second; nothing else on an entry distinguishes them. [`EntryCodec::headers`] returns
    /// the first; this says whether the first is also the only.
    pub fn header_count(&self) -> usize {
        self.file.headers_seen
    }

    /// create a new `EntryCodec` with the specified configuration
    pub fn new(c: EntryCodecConfig) -> Self {
        Self {
            config: c,
            ..Default::default()
        }
    }
    /// calls the appropriate parser based on the current state held in the Codec context
    fn parse_next(&mut self, i: &mut Stream<'_>) -> Result<Option<Entry>, Halt> {
        let blank: ModalResult<_> = multispace0.parse_next(i);
        blank?;

        match self.context.expects {
            DecodeStage::Header => {
                // `Option` and not `unwrap_or_default`: a log with no header and a log whose
                // header carried an empty version must not be the same value, since a rotated or
                // concatenated slow log genuinely has no header.
                //
                // This arm runs again between every pair of entries, because completing an entry
                // returns `expects` to `Header`. So the header must be kept rather than
                // assigned: a plain assignment would overwrite the first file's version with
                // `None` on the next entry. A second header block mid-file means the log was
                // reopened, and the entries after it may have been written by a different server,
                // so the first is kept and the count is recorded.
                let res = opt(log_header).parse_next(i)?;
                self.context.expects = DecodeStage::Time;
                if let Some(h) = res {
                    self.file.headers_seen += 1;
                    if self.file.headers.is_none() {
                        self.file.headers = Some(h);
                    }
                }
            }
            DecodeStage::Time => {
                let dt = parse_entry_time(i)?;
                self.context.time = Some(dt);
                self.context.expects = DecodeStage::Session;
            }
            DecodeStage::Session => {
                let sl = entry_user(i)?;
                self.context.user = Some(sl);
                self.context.expects = DecodeStage::Stats;
            }
            DecodeStage::Stats => {
                let st = parse_entry_stats(i)?;
                self.context.stats = Some(st);
                self.context.expects = DecodeStage::UseDatabase;
            }
            DecodeStage::UseDatabase => {
                // Filed only where the log said it. `USE` is sticky per connection and MySQL
                // writes it when the database changes, so later entries on the same thread
                // inherit a database this entry never mentions. Carrying it forward is a
                // reader's inference over the thread, and it belongs to whoever draws it.
                self.context.use_database = opt(use_database).parse_next(i)?;
                self.context.expects = DecodeStage::SetTimestamp;
            }
            DecodeStage::SetTimestamp => {
                let st = start_timestamp_command(i)?;
                self.context.set_timestamp = Some(st);
                self.context.expects = DecodeStage::Statement;
            }
            DecodeStage::Statement => {
                // `opt` and not a bare call: winnow rewinds only where a combinator takes a
                // checkpoint, so a parser that fails after consuming leaves the stream where it
                // stopped and `sql_lines` below would read the remainder of the line as the
                // statement. `opt` restores the checkpoint on a backtrack and still propagates
                // `Incomplete`, which is what a partial stream needs.
                if let Some(c) = opt(admin_command).parse_next(i)? {
                    self.context.attributes = Some(EntrySqlAttributes {
                        sql: (c.command.clone()),
                        // `None`, because a different parser consumed the line and its framing.
                        // `sql` above is still the log's own bytes here -- the command word -- so
                        // nothing is lost; there is simply no statement text to file. The
                        // `EntryStatement` arm is what says so.
                        sql_raw: None,
                        literals: Vec::new(),
                        use_database: self.context.use_database.clone(),
                        statement: EntryStatement::AdminCommand(c),
                    });
                } else {
                    let mut details = None;

                    if let Ok(Some(d)) = opt(details_comment).parse_next(i) {
                        details = Some(d);
                    }

                    let mut sql_lines = sql_lines(i)?;

                    // The author's own bytes, kept before the render below overwrites
                    // `sql_lines`. `Bytes` is refcounted, so this is an atomic increment and no
                    // copy. It also carries every literal as text even when masking is on,
                    // because masking happens inside `parse_sql` and touches only the tree.
                    let sql_raw = sql_lines.clone();
                    let mut literals = Vec::new();

                    // `str::from_utf8` first and `from_utf8_lossy` only where it refuses: the
                    // borrowed path is what a slow log almost always takes, and the lossy
                    // fallback is kept so that a statement whose bytes are not UTF-8 reaches the
                    // caller rather than stopping the file. It is parsed as decoded, with U+FFFD
                    // in place of each invalid sequence; `sql_raw` keeps the bytes.
                    let text = match std::str::from_utf8(&sql_lines) {
                        Ok(s) => Cow::Borrowed(s),
                        Err(_) => String::from_utf8_lossy(&sql_lines),
                    };

                    let s = if let Ok((mut parsed, ls)) = parse_sql(&text, &self.config.masking) {
                        literals = ls;
                        if parsed.len() == 1 {
                            // With no mapper registered the comment's own pairs are carried
                            // through rather than dropped: `map_comment_context` defaults to
                            // `None`, and a caller taking the default gets what the comment
                            // wrote. The hook is for callers that want to filter, rename or
                            // reject pairs.
                            let context: Option<SqlStatementContext> =
                                details.and_then(|d| match &self.config.map_comment_context {
                                    Some(f) => f(d),
                                    None => SqlStatementContext::new(d),
                                });

                            // Moved out of the `Vec` rather than cloned out of it: the whole AST
                            // would be deep-copied and the original dropped two lines later. The
                            // length is checked one line up, so `pop` is that element.
                            let s = EntrySqlStatement {
                                statement: parsed.pop().expect("length checked above"),
                                context,
                            };

                            // Sized from the author's bytes: the render is within a few bytes of
                            // the text it came from, so one allocation does it where
                            // `to_string()` would start at zero and double.
                            let mut rendered = String::with_capacity(sql_raw.len());
                            let _ = write!(rendered, "{}", s.statement);

                            sql_lines = Bytes::from(rendered);
                            SqlStatement(s)
                        } else {
                            EntryStatement::InvalidStatement(text.into_owned())
                        }
                    } else {
                        EntryStatement::InvalidStatement(text.into_owned())
                    };

                    self.context.attributes = Some(EntrySqlAttributes {
                        sql: sql_lines,
                        sql_raw: Some(sql_raw),
                        literals,
                        use_database: self.context.use_database.clone(),
                        //-- TODO: pull this from the Entry Statement
                        statement: s,
                    });
                }

                let e = self.context.complete().ok_or(Halt::Refused)?;
                self.file.processed += 1;

                return Ok(Some(e));
            }
        }

        Ok(None)
    }

    /// Runs the stages over `src` until an entry completes, the buffer runs out, or a stage
    /// refuses. With `eof` the buffer is the rest of the input and no stage waits for more.
    ///
    /// Each stage is committed as it completes, so a partial entry resumes at the stage it
    /// stopped in rather than being re-read from its start. On an error the buffer is advanced
    /// only past the committed stages, so decoding again reports the same error.
    ///
    /// The buffer is advanced past what was consumed rather than split and refilled, which it
    /// can be because the parsers copy whatever they keep: every `Bytes` this codec produces is
    /// built with `copy_from_slice` or accumulated into a `BytesMut`, and nothing borrows the
    /// input. Consumed is what the stream no longer holds, measured after any reset.
    fn decode_buffer(
        &mut self,
        src: &mut BytesMut,
        eof: bool,
    ) -> Result<Option<Entry>, CodecError> {
        let available = src.len();
        let mut i = Stream::new(&src[..]);
        if eof {
            let _ = i.complete();
        }

        let mut start = i.checkpoint();

        let outcome = loop {
            if i.is_empty() {
                break Ok(None);
            }

            match self.parse_next(&mut i) {
                Ok(Some(e)) => break Ok(Some(e)),
                Ok(None) => {
                    debug!("preparing input for next parser\n");
                    start = i.checkpoint();
                }
                // Back to the last completed stage, not to the start of the buffer. The stages
                // before it are committed: their values are in `self.context` and their bytes
                // are spent, which is what makes this a streaming decoder rather than one that
                // re-reads a partial entry on every poll.
                Err(Halt::Incomplete) if !eof => {
                    i.reset(&start);
                    break Ok(None);
                }
                Err(halt) => {
                    i.reset(&start);
                    // A prefix can be refused before its line has arrived. The error waits for
                    // the whole line, so that what it quotes does not depend on where the reads
                    // cut the input.
                    if !eof && !i.trim_ascii_start().contains(&b'\n') {
                        break Ok(None);
                    }
                    break Err(self.error(halt, &i, eof));
                }
            }
        };

        let remaining = i.len();
        src.advance(available - remaining);

        outcome
    }

    /// The error for a stage that stopped on `rest`.
    ///
    /// At the end of the input a statement with no terminator, or a last line with no line
    /// ending, is the input ending inside the entry rather than a line that cannot be read.
    fn error(&self, halt: Halt, rest: &[u8], eof: bool) -> CodecError {
        let stage = self.context.expects;
        let entry = self.file.processed;
        let line = excerpt(rest);

        match halt {
            Halt::Incomplete => CodecError::Truncated { stage, entry, line },
            Halt::Refused
                if eof
                    && (stage == DecodeStage::Statement || !rest.trim_ascii().contains(&b'\n')) =>
            {
                CodecError::Truncated { stage, entry, line }
            }
            Halt::Refused => CodecError::Malformed { stage, entry, line },
        }
    }
}

/// The first line of `rest` that is not blank, cut to at most [`EXCERPT_MAX`] bytes at a
/// character boundary and lossily decoded.
fn excerpt(rest: &[u8]) -> String {
    let rest = rest.trim_ascii_start();
    let line = &rest[..rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len())];
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    let mut end = line.len().min(EXCERPT_MAX);
    // Back up off a UTF-8 continuation byte, so the cut does not split a character.
    while end > 0 && end < line.len() && line[end] & 0xC0 == 0x80 {
        end -= 1;
    }

    String::from_utf8_lossy(&line[..end]).into_owned()
}

impl Decoder for EntryCodec {
    type Item = Entry;
    type Error = CodecError;

    /// Decodes the next entry, or returns `Ok(None)` where the buffer ends inside one.
    ///
    /// Each line of an entry is committed as it is read, so a partial entry resumes at the line
    /// it stopped on rather than being re-read from its start.
    ///
    /// There is no length limit: a statement with no terminating `;` is buffered until one
    /// arrives or the input ends.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        self.decode_buffer(src, false)
    }

    /// Decodes what is left at end of input and ensures that no unprocessed bytes remain.
    ///
    /// Input that ends inside an entry is [`CodecError::Truncated`], so a truncated log is an
    /// error rather than a quiet end. Whitespace after the last entry is not.
    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(frame) = self.decode_buffer(buf, true)? {
            return Ok(Some(frame));
        }

        let stage = match self.context.expects {
            // The `use` line is optional, so what an entry ending there lacks is the next line.
            DecodeStage::UseDatabase => DecodeStage::SetTimestamp,
            stage => stage,
        };
        let mid_entry = !matches!(stage, DecodeStage::Header | DecodeStage::Time);

        if mid_entry || buf.iter().any(|b| !b.is_ascii_whitespace()) {
            return Err(CodecError::Truncated {
                stage,
                entry: self.file.processed,
                line: excerpt(buf),
            });
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::codec::EntryCodec;
    use crate::parser::parse_sql;
    use crate::types::EntryStatement::SqlStatement;
    use crate::types::{
        Entry, EntryCall, EntrySession, EntrySqlAttributes, EntrySqlStatement,
        EntrySqlStatementObject, EntryStatement, EntryStats,
    };
    use crate::{EntryCodecConfig, EntryMasking, SqlStatementContext};
    use bytes::Bytes;
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::default::Default;
    use std::io::Cursor;
    use std::ops::AddAssign;

    use tokio::fs::File;
    use tokio_util::codec::Framed;
    use winnow::error::InputError;
    use winnow_iso8601::datetime::datetime;

    #[tokio::test]
    async fn parses_select_entry() {
        let sql_comment = "-- request_id: apLo5wdqkmKw4W7vGfiBc5, file: src/endpoints/original/mod\
        .rs, method: notifications(), line: 38";
        let sql = "SELECT film.film_id AS FID, film.title AS title, film.description AS \
        description, category.name AS category, film.rental_rate AS price FROM category LEFT JOIN \
         film_category ON category.category_id = film_category.category_id LEFT JOIN film ON \
         film_category.film_id = film.film_id GROUP BY film.film_id, category.name;";
        //NOTE: decimal places were shortened by parser, so this time is shortened
        let mut time = "2018-02-05T02:46:47.273Z";

        let entry = format!(
            "# Time: {}
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
use mysql;
SET timestamp=1517798807;
{}
{},
",
            time, sql_comment, sql
        );

        let mut eb = entry.as_bytes().to_vec();

        // No mapper: the default carries the comment's pairs through under the names the
        // comment used.
        let config = EntryCodecConfig::default();

        let mut ff = Framed::new(Cursor::new(&mut eb), EntryCodec::new(config));
        let e = ff.next().await.unwrap().unwrap();

        let stmts = parse_sql(sql, &EntryMasking::None).unwrap();

        let expected_stmt = EntrySqlStatement {
            statement: stmts.0.first().unwrap().clone(),
            context: SqlStatementContext::new(HashMap::from([
                (
                    Bytes::from("request_id"),
                    Bytes::from("apLo5wdqkmKw4W7vGfiBc5"),
                ),
                (
                    Bytes::from("file"),
                    Bytes::from("src/endpoints/original/mod.rs"),
                ),
                (Bytes::from("method"), Bytes::from("notifications()")),
                (Bytes::from("line"), Bytes::from("38")),
            ])),
        };

        let expected_sql = sql.trim().strip_suffix(";").unwrap();

        let expected_entry = Entry {
            call: EntryCall::new(
                //TODO: handle error
                datetime::<_, InputError<_>>(&mut time).unwrap(),
                1517798807,
            ),
            session: EntrySession {
                user_name: Bytes::from("msandbox"),
                sys_user_name: Bytes::from("msandbox"),
                host_name: Some(Bytes::from("localhost")),
                ip_address: None,
                thread_id: 10,
            },
            stats: EntryStats {
                query_time: 0.000352,
                lock_time: 0.0,
                rows_sent: 0,
                rows_examined: 0,
            },
            sql_attributes: EntrySqlAttributes {
                sql_raw: Some(sql.trim().into()),
                literals: vec![],
                // The entry carries `use mysql;`: the schema its unqualified relations live in.
                use_database: Some("mysql".into()),
                sql: Bytes::from(expected_sql),
                statement: SqlStatement(expected_stmt),
            },
        };

        assert_eq!(e, expected_entry);
    }

    #[tokio::test]
    async fn parses_multiple_entries() {
        let entries = "# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
-- ID: 123, caller: hello_world()
SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT JOIN film ON film_category.film_id = film.film_id
GROUP BY film.film_id, category.name;
# Time: 2018-02-05T02:46:47.273787Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798808;
ALTER TABLE `film` DISABLE KEYS;
# Time: 2018-02-05T02:46:47.273788Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798809;
-- ID: 456, caller: hello_world()
SELECT film2.film_id AS FID, film2.title AS title, film2.description AS description, category.name
AS category, film2.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT
JOIN film2 ON film_category.film_id = film2.film_id
GROUP BY film2.film_id, category.name;
";

        let mut eb = entries.as_bytes().to_vec();

        let mut ff = Framed::with_capacity(Cursor::new(&mut eb), EntryCodec::default(), 4);

        let mut found = 0;
        let mut invalid = 0;

        while let Some(res) = ff.next().await {
            let e = res.unwrap();
            found.add_assign(1);

            if let EntryStatement::InvalidStatement(_) = e.sql_attributes.statement {
                invalid.add_assign(1);
            }
        }

        assert_eq!(found, 3, "found");
        // The subject is a log that mixes parseable and unparseable statements. The middle
        // entry is `ALTER TABLE … DISABLE KEYS`, which MySQL runs and `sqlparser` refuses.
        assert_eq!(
            invalid, 1,
            "the mix is the subject, so the arm keeps a witness"
        );
    }

    #[tokio::test]
    async fn parses_select_objects() {
        let sql = String::from("SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
    FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT
    JOIN film ON film_category.film_id = film.film_id LEFT JOIN film AS dupe_film ON film_category
    .film_id = dupe_film.film_id LEFT JOIN other.film AS other_film ON other_film.film_id =
    film_category.film_id
    GROUP BY film.film_id, category.name;");

        let entry = format!(
            "# Time: 2018-02-05T02:46:47.273786Z
    # User@Host: msandbox[msandbox] @ localhost []  Id:    10
    # Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
    SET timestamp=1517798807;
    {}",
            sql
        );

        let expected = vec![
            EntrySqlStatementObject {
                schema_name: None,
                object_name: "category".as_bytes().into(),
            },
            EntrySqlStatementObject {
                schema_name: None,
                object_name: "film".as_bytes().into(),
            },
            EntrySqlStatementObject {
                schema_name: None,
                object_name: "film_category".as_bytes().into(),
            },
            EntrySqlStatementObject {
                schema_name: Some("other".as_bytes().into()),
                object_name: "film".as_bytes().into(),
            },
        ];

        let mut eb = entry.as_bytes().to_vec();

        let mut ff = Framed::new(Cursor::new(&mut eb), EntryCodec::default());
        let e = ff.next().await.unwrap().unwrap();

        match e.sql_attributes.statement() {
            SqlStatement(s) => {
                assert_eq!(s.objects(), expected);
                assert_eq!(s.sql_type().to_string(), "SELECT".to_string());
            }
            _ => {
                panic!("should have parsed sql as SqlStatement")
            }
        }
    }

    #[tokio::test]
    async fn parse_log_file() {
        let f = File::open("assets/slow-test-queries.log").await.unwrap();
        let mut ff = Framed::new(f, EntryCodec::default());

        let mut i = 0;

        while let Some(res) = ff.next().await {
            let _ = res.unwrap();
            i.add_assign(1);
        }

        assert_eq!(i, 310);
    }

    #[tokio::test]
    async fn parse_mysql_log_file_small_capacity() {
        let f = File::open("assets/slow-test-queries.log").await.unwrap();
        let mut ff = Framed::with_capacity(f, EntryCodec::default(), 4);

        let mut i = 0;

        while let Some(res) = ff.next().await {
            let _ = res.unwrap();
            i.add_assign(1);
        }

        assert_eq!(i, 310);
    }
}

#[cfg(test)]
mod admin_command_completeness {
    use crate::parser::{Stream, admin_command};
    use crate::{EntryCodec, EntryStatement};
    use futures::StreamExt;
    use std::collections::BTreeMap;
    use tokio::fs::File;
    use tokio_util::codec::FramedRead;
    use winnow::combinator::opt;
    use winnow::stream::AsBytes;
    use winnow::{Parser, Partial};

    /// Every `# administrator command:` line is an `AdminCommand`, including the multi-word ones.
    /// `assets/slow-test-queries.log` holds sixteen, three of them `Init DB` or `Register Slave`.
    ///
    /// A command parser that stopped at the first space would fail mid-line, and winnow leaves
    /// the stream where a failed parser stopped, so `sql_lines` would file the remainder as
    /// `InvalidStatement("DB;")` / `InvalidStatement("Slave;")`.
    #[tokio::test]
    async fn multi_word_admin_commands_survive() {
        let fr = FramedRead::with_capacity(
            File::open("assets/slow-test-queries.log").await.unwrap(),
            EntryCodec::default(),
            30_000_000,
        );

        let mut commands: BTreeMap<String, usize> = BTreeMap::new();
        for e in fr.collect::<Vec<_>>().await.into_iter().flatten() {
            match &e.sql_attributes.statement {
                EntryStatement::AdminCommand(c) => {
                    *commands
                        .entry(String::from_utf8_lossy(&c.command).into_owned())
                        .or_default() += 1;
                }
                EntryStatement::InvalidStatement(s) => assert!(
                    !matches!(s.trim(), "DB;" | "Slave;"),
                    "a fragment of an admin command was filed as SQL: {s:?}"
                ),
                _ => {}
            }
        }

        assert_eq!(commands.get("Quit"), Some(&12));
        assert_eq!(commands.get("Ping"), Some(&1));
        assert_eq!(commands.get("Init DB"), Some(&2), "two words");
        assert_eq!(commands.get("Register Slave"), Some(&1), "two words");
        assert_eq!(commands.values().sum::<usize>(), 16);
    }

    /// And the other half: a failed attempt must not consume.
    ///
    /// winnow rewinds only where a combinator takes a checkpoint, so a bare `admin_command(i)`
    /// discarded on `Err` would leave the stream mid-line. Here the command line has no
    /// terminating `;`, so the parser matches its prefix and then fails.
    ///
    /// What this does not guard: it pins `opt`'s contract, not the codec's use of it. Revert
    /// `admin_command` to a single-word matcher and this still passes, because the `opt` here
    /// restores either way; only `multi_word_admin_commands_survive` notices that. Nothing in
    /// this file fails if the `opt` at the call site is dropped while the command parser stays
    /// correct -- with both halves in place that rewind is defence in depth.
    #[test]
    fn a_failed_admin_command_does_not_consume() {
        let input = b"# administrator command: Init DB
SELECT 1;
";
        let mut i: Stream = Partial::new(&input[..]);

        let parsed = opt(admin_command).parse_next(&mut i).unwrap();

        assert!(
            parsed.is_none(),
            "no `;`, so this is not a complete command"
        );
        assert_eq!(
            i.as_bytes(),
            &input[..],
            "the stream must be exactly where it started"
        );
    }
}

/// The relation graph, measured over every statement in `assets/slow-test-queries.log` rather
/// than over hand-written SQL.
///
/// A regression corpus: the log is a sandbox startup and a `mysqldump` restore. What it can prove
/// is that the walk over every real parse in it loses nothing `objects()` held, and that the one
/// non-tree join graph in it is found.
#[cfg(test)]
mod graph_census {
    use crate::codec::EntryCodec;
    use crate::{EntryStatement, RelationRole, ScopeKind};
    use futures::StreamExt;
    use std::ops::AddAssign;
    use std::ops::Not;
    use tokio::fs::File;
    use tokio_util::codec::Framed;

    /// The server the file declares.
    ///
    /// Every claim about MySQL's *behaviour* holds for a server version, and the first line of a
    /// slow log is the only place the document names one. This corpus says 5.7.20.
    ///
    /// It is an `Option` because a log that begins mid-stream has no header, and that must not
    /// look like a header whose version was empty.
    #[tokio::test]
    async fn the_log_declares_the_server_that_wrote_it() {
        let f = File::open("assets/slow-test-queries.log").await.unwrap();
        let mut ff = Framed::new(f, EntryCodec::default());
        assert!(
            ff.codec().headers().is_none(),
            "nothing is known before a line has been read"
        );
        let _ = ff.next().await.unwrap().unwrap();
        let h = ff.codec().headers().expect("this file opens with a header");
        assert_eq!(
            h.version().as_ref(),
            b"5.7.20-log (MySQL Community Server (GPL))."
        );
        assert_eq!(h.tcp_port(), Some(12345));

        // Unparsed on purpose. Splitting this into numbers is a reading, and `-log` here,
        // `-MariaDB` elsewhere and `-percona` elsewhere again are three different grammars for
        // the same field. Whoever needs a comparison makes it, on the bytes the server wrote.
        assert!(h.version().as_ref().starts_with(b"5.7."));

        // And it survives the whole file. Completing an entry returns `expects` to `Header`, so
        // the header arm runs between every pair of entries and must not overwrite what it
        // found. Drain the stream and ask again.
        while (ff.next().await).is_some() {}
        let h = ff
            .codec()
            .headers()
            .expect("the regime is a fact about the FILE");
        assert!(h.version().as_ref().starts_with(b"5.7."));

        // One header, so the first is also the only.
        assert_eq!(ff.codec().header_count(), 1);
    }

    #[tokio::test]
    async fn the_graph_census_of_the_shipped_log() {
        let f = File::open("assets/slow-test-queries.log").await.unwrap();
        let mut ff = Framed::new(f, EntryCodec::default());

        let (mut parsed, mut with_graph, mut occurrences, mut edges) = (0, 0, 0usize, 0usize);
        let (mut named_only, mut non_tree, mut view_bodies) = (0usize, 0usize, 0usize);
        let mut quoted = 0usize;
        let (mut altered, mut dropped) = (0usize, 0usize);
        let (mut lock_x, mut lock_s, mut analyzed) = (0usize, 0usize, 0usize);
        let mut missed: Vec<String> = Vec::new();
        let mut view_targets = 0usize;

        while let Some(res) = ff.next().await {
            let e = res.unwrap();
            parsed.add_assign(1);
            let EntryStatement::SqlStatement(s) = &e.sql_attributes.statement else {
                continue;
            };
            with_graph += 1;
            let g = s.relation_graph();
            occurrences += g.occurrences.len();
            edges += g.edges.len();
            altered += g
                .occurrences
                .iter()
                .filter(|o| o.role == RelationRole::AlterTarget)
                .count();
            dropped += g
                .occurrences
                .iter()
                .filter(|o| o.role == RelationRole::DropTarget)
                .count();
            let n = |r: RelationRole| g.occurrences.iter().filter(|o| o.role == r).count();
            lock_x += n(RelationRole::LockExclusiveTarget);
            lock_s += n(RelationRole::LockSharedTarget);
            analyzed += n(RelationRole::AnalyzeTarget);
            if g.measures().cycle_space > 0 {
                non_tree += 1;
            }
            if g.scopes.iter().any(|sc| sc.kind == ScopeKind::ViewBody) {
                view_bodies += 1;
                named_only += g
                    .occurrences
                    .iter()
                    .filter(|o| g.in_view_body(o.occ))
                    .count();
            }
            // Nothing `objects()` found may be missing from the graph; the reverse is allowed.
            //
            // The comparison strips backticks: `objects()` builds its names with `to_string()`,
            // which renders the quote style, so `` `actor` `` and `actor` are two entries there.
            // The graph carries the unquoted value.
            for o in s.objects() {
                let raw = o.object_name();
                let bare = raw.trim_matches('`');
                if raw != bare {
                    quoted.add_assign(1);
                }
                if !g
                    .occurrences
                    .iter()
                    .any(|r| r.object_name.as_deref() == Some(bare.as_bytes()))
                {
                    missed.push(format!("{bare} <- {:?}", s.sql_type()));
                }
            }
            view_targets += g
                .occurrences
                .iter()
                .filter(|r| r.role == RelationRole::CreateTarget && g.in_view_body(r.occ).not())
                .filter(|_| g.scopes.iter().any(|sc| sc.kind == ScopeKind::ViewBody))
                .count();
        }

        missed.sort();
        missed.dedup();
        // One miss, and it is not a relation. `SHOW TABLES FROM mysql` names a schema, and
        // `ShowStatementIn.parent_name` carries a `visit_relation` annotation, so `objects()`
        // files the schema `mysql` as though it were a table. The graph declines to.
        assert_eq!(
            missed,
            vec!["mysql <- ShowTables".to_string()],
            "the graph may hold more than objects(), and may lose nothing that is a relation"
        );

        assert_eq!(parsed, 310);
        // MySQL's `/*!40101 … */` version gates are executed as the server executes them, so
        // `mysqldump`'s session settings parse. None of them names a relation.
        assert_eq!(with_graph, 259, "statements with an AST to walk");

        // The seven `CREATE VIEW`s are the only multi-relation statements here, and all 39
        // relations they mention sit in a view body: named, never read. The flat `objects` set
        // cannot tell a table scanned from a table named in a DDL body.
        assert_eq!(view_bodies, 7, "every multi-relation statement is a view");
        assert_eq!(named_only, 39, "relations named in a body, not scanned");

        // One non-tree join graph, `actor_info`: its correlated subquery rebinds `fa` and `fc`,
        // and the two correlation edges close a cycle. Two routes to the same kernel agree
        // exactly where the descent is a tree, so this is the case that can tell them apart.
        assert_eq!(non_tree, 1, "actor_info, and nothing else");

        // No alters: every `ALTER TABLE` in this log says `DISABLE KEYS` or `ENABLE KEYS`, which
        // `sqlparser` refuses, so those entries are invalid and reach no graph at all.
        //
        // Ten drops against eleven `DROP` lines: `DROP DATABASE IF EXISTS sakila` names a schema
        // and not a relation, and the walk declines it.
        assert_eq!(
            (altered, dropped),
            (0, 10),
            "the DDL that names an existing table"
        );
        // Sixteen explicit write locks: `mysqldump` writes `LOCK TABLES `t` WRITE` before each
        // table's inserts, and `LockTables.tables` carries no `visit_relation` annotation, so
        // only the graph sees them.
        //
        // Zero analyzed, though this log runs an `ANALYZE TABLE` over sixteen tables. MySQL's
        // `ANALYZE TABLE` takes a list; `sqlparser`'s `Analyze` carries a single `table_name`,
        // so the multi-table form is refused and the entry is invalid. A role with no witness
        // here may be a role the log never exercised or a form the grammar cannot read.
        assert_eq!((lock_x, lock_s, analyzed), (16, 0, 0));
        assert_eq!(occurrences, 147);
        assert_eq!(edges, 33);

        // The seven views this log creates, each a create target outside its own body.
        assert_eq!(view_targets, 7);

        // 46 names `objects()` reports wrapped in backticks and the graph reports bare.
        assert_eq!(quoted, 46, "names objects() spells with backticks");
    }
}

/// What the author wrote, against what the reader made of it.
///
/// `EntrySqlAttributes::sql` is the AST rendered back to text on every statement that parsed;
/// `sql_raw` is the author's bytes, kept whether or not the statement parsed.
#[cfg(test)]
mod the_author_and_the_reader {
    use crate::codec::EntryCodec;
    use crate::{EntryStatement, LiteralKind};
    use futures::StreamExt;
    use std::io::Cursor;
    use tokio::fs::File;
    use tokio_util::codec::Framed;

    #[tokio::test]
    async fn the_render_is_not_the_document_and_now_both_are_kept() {
        let f = File::open("assets/slow-test-queries.log").await.unwrap();
        let mut ff = Framed::new(f, EntryCodec::default());

        let (mut n, mut parsed, mut differs, mut newlines_lost, mut lowercase) = (0, 0, 0, 0, 0);
        let (mut with_db, mut literals, mut entries_with_literals) = (0, 0usize, 0);
        let mut kinds = std::collections::BTreeMap::new();

        while let Some(r) = ff.next().await {
            let e = r.unwrap();
            n += 1;
            let a = &e.sql_attributes;

            if a.use_database.is_some() {
                with_db += 1;
            }
            literals += a.literals.len();
            if !a.literals.is_empty() {
                entries_with_literals += 1;
            }
            for l in &a.literals {
                *kinds.entry(l.kind).or_insert(0) += 1;
            }

            match &a.statement {
                EntryStatement::SqlStatement(_) => {
                    parsed += 1;
                    let raw = String::from_utf8_lossy(
                        a.sql_raw
                            .as_ref()
                            .expect("a parsed statement has raw bytes"),
                    )
                    .to_string();
                    let rendered = String::from_utf8_lossy(&a.sql).to_string();
                    if raw.trim_end().trim_end_matches(';') != rendered {
                        differs += 1;
                    }
                    if raw.contains('\n') && !rendered.contains('\n') {
                        newlines_lost += 1;
                    }
                    if raw.contains("select ") || raw.contains("from ") {
                        lowercase += 1;
                    }
                }
                // An administrator command has no statement text: a different parser consumed
                // the line and its framing. `sql` there is still the log's own bytes.
                EntryStatement::AdminCommand(_) => assert!(a.sql_raw.is_none()),
                // And an unparseable statement keeps its bytes too.
                EntryStatement::InvalidStatement(_) => assert!(a.sql_raw.is_some()),
            }
        }

        assert_eq!((n, parsed), (310, 259));

        // Three quarters of the parsed statements do not render back to what the author wrote.
        assert_eq!(differs, 195);
        assert_eq!(newlines_lost, 62, "multi-line statements flattened to one");
        assert_eq!(lowercase, 9, "keywords the author did not capitalise");

        // The author's subject, recovered whether or not masking is on, because the bytes carry
        // it even when the tree does not.
        assert_eq!(literals, 323);
        assert_eq!(entries_with_literals, 98);
        assert_eq!(kinds.get(&LiteralKind::Number), Some(&114));
        assert_eq!(kinds.get(&LiteralKind::SingleQuotedString), Some(&209));

        // `USE` is written only when the database changes, so two entries in this log carry one;
        // that the other 308 inherit it is an inference this crate declines to draw.
        assert_eq!(with_db, 2);
    }

    /// A shard of a log carries no header, and the file scope is what travels with it.
    ///
    /// The codec carries its file scope across buffer boundaries, which is what a `Decoder` is.
    /// A shard is a different file and only the first one holds the header, so the scope has to
    /// be handed across. Three readings of one log:
    ///
    /// | | version | header_count | processed |
    /// |---|---|---|---|
    /// | the whole file | present | 1 | all |
    /// | the tail, read fresh | `None` | 0 | the tail's own |
    /// | the tail, resumed | present | 1 | continues the prefix's count |
    ///
    /// `processed` continuing is what lets a caller recover each entry's position in the whole
    /// log.
    #[tokio::test]
    async fn a_shard_carries_no_header_and_the_file_scope_is_what_travels() {
        let whole = tokio::fs::read("assets/slow-test-queries.log")
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&whole).into_owned();
        let lines: Vec<&str> = text.lines().collect();
        let first = lines.iter().position(|l| l.starts_with("# Time:")).unwrap();
        let starts: Vec<usize> = (first..lines.len())
            .filter(|i| lines[*i].starts_with("# Time:"))
            .collect();
        let cut = starts[100];
        let (head, tail) = (
            lines[..cut].join("\n") + "\n",
            lines[cut..].join("\n") + "\n",
        );

        let run = |bytes: String, codec: EntryCodec| async move {
            let mut f = Framed::new(Cursor::new(bytes.into_bytes()), codec);
            let mut n = 0usize;
            while let Some(r) = f.next().await {
                r.unwrap();
                n += 1;
            }
            (n, f.into_parts().codec)
        };

        let (whole_n, w) = run(text.clone() + "\n", EntryCodec::default()).await;
        assert_eq!(w.header_count(), 1);
        assert!(w.headers().is_some());

        let (head_n, h) = run(head, EntryCodec::default()).await;
        let scope = h.file_scope().clone();
        assert_eq!(scope.header_count(), 1);
        assert_eq!(scope.processed(), head_n);

        // Read fresh, the tail states no server at all.
        let (tail_n, fresh) = run(tail.clone(), EntryCodec::default()).await;
        assert_eq!(fresh.header_count(), 0, "a shard has no header of its own");
        assert!(fresh.headers().is_none());
        assert_eq!(fresh.file_scope().processed(), tail_n);

        // Resumed, it states the prefix's server and continues the prefix's count.
        let (resumed_n, resumed) = run(tail, EntryCodec::resume(Default::default(), scope)).await;
        assert_eq!(resumed_n, tail_n, "resuming changes no entry");
        assert_eq!(resumed.header_count(), 1);
        assert_eq!(resumed.headers(), w.headers());
        assert_eq!(resumed.file_scope().processed(), whole_n);
        assert_eq!(head_n + tail_n, whole_n, "and the split loses nothing");
        assert!(head_n > 0 && tail_n > 0, "an empty shard would say nothing");
    }
}

/// Every shape of entry a MySQL-compatible server writes, each followed by a plain entry that a
/// mis-framed first entry would take down with it, and each read in every chunk size.
#[cfg(test)]
mod every_shape_a_server_writes {
    use crate::Entry;
    use crate::codec::{CodecError, EntryCodec};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    pub(super) const HEADER: &str = "/home/karl/mysql/my-5.7/bin/mysqld, Version: 5.7.20-log (MySQL Community Server (GPL)). started with:
Tcp port: 12345  Unix socket: /tmp/12345/mysql_sandbox12345.sock
Time                 Id Command    Argument
";
    pub(super) const TIME: &str = "# Time: 2018-02-05T02:46:43.015898Z\n";
    pub(super) const SESSION: &str = "# User@Host: msandbox[msandbox] @ localhost []  Id:     3\n";
    pub(super) const STATS: &str =
        "# Query_time: 0.000016  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0\n";
    pub(super) const SET: &str = "SET timestamp=1517798803;\n";

    /// Every entry decoded from `log` fed to the decoder `chunk` bytes at a time, as
    /// `FramedRead` would, and the first error if there is one.
    pub(super) fn feed(log: &[u8], chunk: usize) -> (Vec<Entry>, Option<CodecError>) {
        let mut codec = EntryCodec::default();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();

        for piece in log.chunks(chunk.max(1)) {
            buf.extend_from_slice(piece);
            loop {
                match codec.decode(&mut buf) {
                    Ok(Some(e)) => out.push(e),
                    Ok(None) => break,
                    Err(e) => return (out, Some(e)),
                }
            }
        }
        loop {
            match codec.decode_eof(&mut buf) {
                Ok(Some(e)) => out.push(e),
                Ok(None) => return (out, None),
                Err(e) => return (out, Some(e)),
            }
        }
    }

    /// `log` read whole and in chunks of 1 to 16 bytes and a few larger, which must all agree.
    pub(super) fn read(log: &str) -> (Vec<Entry>, Option<CodecError>) {
        let (whole, error) = feed(log.as_bytes(), log.len());
        let said = error.as_ref().map(|e| e.to_string());

        for chunk in (1..=16).chain([31, 64, 257]) {
            let (cut, cut_error) = feed(log.as_bytes(), chunk);
            assert_eq!(cut, whole, "chunks of {chunk}: {log}");
            assert_eq!(cut_error.map(|e| e.to_string()), said, "chunks of {chunk}");
        }

        (whole, error)
    }

    /// The shipped log, fed a byte at a time and in odd chunks, decodes to exactly what it
    /// decodes to whole.
    #[test]
    fn the_shipped_log_reads_the_same_in_any_chunk_size() {
        let log = std::fs::read("assets/slow-test-queries.log").unwrap();
        let (whole, error) = feed(&log, log.len());
        assert!(error.is_none());
        assert_eq!(whole.len(), 310);

        for chunk in [1, 7, 4096] {
            let (cut, error) = feed(&log, chunk);
            assert!(error.is_none(), "chunks of {chunk}");
            assert!(cut == whole, "chunks of {chunk}");
        }
    }
}

/// What the decoder cannot read is an error that says where, never a panic and never a skip.
#[cfg(test)]
mod a_line_that_cannot_be_read_is_an_error {
    use super::every_shape_a_server_writes::{HEADER, SESSION, SET, STATS, TIME, feed, read};
    use crate::codec::{CodecError, DecodeStage, EntryCodec};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    /// The stage and the line of a `Malformed`, and nothing else.
    fn malformed(text: &str) -> (DecodeStage, String) {
        match read(text) {
            (_, Some(CodecError::Malformed { stage, line, .. })) => (stage, line),
            other => panic!("not malformed: {other:?}"),
        }
    }

    #[test]
    fn a_line_its_stage_refuses_names_the_stage_and_the_line() {
        for (text, stage, line) in [
            (
                format!(
                    "{HEADER}{TIME}# User@Host: root[root] localhost []\n{STATS}{SET}SELECT 1;\n"
                ),
                DecodeStage::Session,
                "# User@Host: root[root] localhost []",
            ),
            (
                format!("{HEADER}not an entry\n{TIME}{SESSION}{STATS}{SET}SELECT 1;\n"),
                DecodeStage::Time,
                "not an entry",
            ),
            // Refused on its first bytes, and still quoted whole in every chunk size.
            (
                format!("{HEADER}{TIME}# Usr@Host: a[a] @ h []  Id: 1\n{STATS}{SET}SELECT 1;\n"),
                DecodeStage::Session,
                "# Usr@Host: a[a] @ h []  Id: 1",
            ),
            (
                format!("{HEADER}{TIME}{SESSION}{STATS}SE timestamp=1;\nSELECT 1;\n"),
                DecodeStage::SetTimestamp,
                "SE timestamp=1;",
            ),
        ] {
            assert_eq!(malformed(&text), (stage, line.to_string()), "{text}");
        }
    }

    /// The error carries at most 200 bytes of the line, cut at a character, and never the rest
    /// of the file.
    #[test]
    fn an_error_quotes_a_bounded_line() {
        let long = "é".repeat(5_000);
        let text = format!("{HEADER}# Time: {long}\n{SESSION}{STATS}{SET}SELECT 1;\n");

        let (stage, line) = malformed(&text);
        assert_eq!(stage, DecodeStage::Time);
        assert!(line.len() <= 200 && line.len() >= 190, "{}", line.len());
        assert!(line.starts_with("# Time: é") && !line.contains('\u{FFFD}'));

        let (_, error) = read(&text);
        let said = error.unwrap().to_string();
        assert!(
            said.starts_with("cannot read the time line of entry 0: "),
            "{said}"
        );
        assert!(said.len() < 300 && !said.contains("SELECT"), "{said}");
    }

    /// Input that ends inside an entry, which MySQL never writes, is `Truncated`: a caller can
    /// tell a cut log from a whole one.
    #[test]
    fn input_that_ends_inside_an_entry_is_truncated() {
        for (text, stage) in [
            (
                format!("{HEADER}{TIME}{SESSION}{STATS}{SET}SELECT 1"),
                DecodeStage::Statement,
            ),
            (
                format!("{HEADER}{TIME}{SESSION}{STATS}{SET}SELECT 1\n"),
                DecodeStage::Statement,
            ),
            (
                format!("{HEADER}{TIME}{SESSION}{STATS}{SET}"),
                DecodeStage::Statement,
            ),
            (
                format!("{HEADER}{TIME}{SESSION}{STATS}"),
                DecodeStage::SetTimestamp,
            ),
            (
                format!("{HEADER}{TIME}{SESSION}# Query_time: 0.1"),
                DecodeStage::Stats,
            ),
            (format!("{HEADER}{TIME}"), DecodeStage::Session),
        ] {
            match read(&text) {
                (
                    entries,
                    Some(CodecError::Truncated {
                        stage: s, entry: 0, ..
                    }),
                ) => {
                    assert!(entries.is_empty());
                    assert_eq!(s, stage, "{text:?}");
                }
                other => panic!("{text:?}: {other:?}"),
            }
        }

        // Bytes that are not UTF-8 are quoted lossily rather than stopping the decoder.
        let mut text = format!("{HEADER}{TIME}{SESSION}{STATS}{SET}SELECT ").into_bytes();
        text.extend_from_slice(b"\xff\xfe");
        match feed(&text, 5) {
            (_, Some(CodecError::Truncated { line, .. })) => {
                assert_eq!(line, "SELECT \u{FFFD}\u{FFFD}")
            }
            other => panic!("{other:?}"),
        }

        // And a log that ends between entries is whole.
        let (entries, error) = read(&format!(
            "{HEADER}{TIME}{SESSION}{STATS}{SET}SELECT 1;\n\n  \n"
        ));
        assert!(error.is_none() && entries.len() == 1);
        let (entries, error) = read(HEADER);
        assert!(error.is_none() && entries.is_empty());
    }

    /// The decoder does not skip what it refused: asked again, it refuses again.
    #[test]
    fn an_error_is_not_skipped() {
        let text = format!("{HEADER}{TIME}# User@Host: nobody\n{STATS}{SET}SELECT 1;\n");
        let mut codec = EntryCodec::default();
        let mut buf = BytesMut::from(text.as_bytes());

        let first = codec.decode(&mut buf).unwrap_err().to_string();
        let second = codec.decode(&mut buf).unwrap_err().to_string();
        assert_eq!(first, second);
        assert!(
            first.starts_with("cannot read the session line of entry 0"),
            "{first}"
        );
    }
}
