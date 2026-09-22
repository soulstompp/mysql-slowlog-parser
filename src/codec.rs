use crate::codec::EntryError::MissingField;
use crate::parser::{
    HeaderLines, Stream, admin_command, details_comment, entry_user, log_header, parse_entry_stats,
    parse_entry_time, parse_sql, sql_lines, start_timestamp_command, use_database,
};
use crate::types::EntryStatement::SqlStatement;
use crate::types::{Entry, EntryCall, EntrySqlAttributes, EntrySqlStatement, EntryStatement};
use crate::{EntryCodecConfig, SessionLine, SqlStatementContext, StatsLine};
use bytes::{Bytes, BytesMut};
use log::debug;
use std::default::Default;
use std::fmt::{Display, Formatter};
use std::ops::AddAssign;
use thiserror::Error;
use tokio::io;
use tokio_util::codec::Decoder;
use winnow::ModalResult;
use winnow::Parser;
use winnow::ascii::multispace0;
use winnow::combinator::opt;
use winnow::error::ErrMode;
use winnow::stream::AsBytes;
use winnow::stream::Stream as _;
use winnow_datetime::DateTime;

const LENGTH_MAX: usize = 10000000000;

/// Error when building an entry
#[derive(Error, Debug)]
pub enum EntryError {
    /// a field is missing from the entry
    #[error("entry field is missing: {0}")]
    MissingField(String),
    /// an entry contains a duplicate id
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

/// Errors for problems when reading frames from the source
#[derive(Debug, Error)]
pub enum CodecError {
    /// a problem from the IO layer below caused the error
    #[error("file read error: {0}")]
    IO(#[from] io::Error),
    /// a new entry started before the previous one was completed
    #[error("found start of new entry before entry completed at line: {0}")]
    IncompleteEntry(EntryError),
}

#[derive(Debug)]
enum CodecExpect {
    Header,
    Time,
    User,
    Stats,
    UseDatabase,
    StartTimeStamp,
    Sql,
}

impl Default for CodecExpect {
    fn default() -> Self {
        Self::Header
    }
}

impl Display for CodecExpect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            CodecExpect::Header => "header",
            CodecExpect::Time => "time",
            CodecExpect::User => "user",
            CodecExpect::Stats => "stats",
            CodecExpect::UseDatabase => "use database",
            CodecExpect::StartTimeStamp => "start time stamp statement",
            CodecExpect::Sql => "sql statement",
        };
        write!(f, "{}", out)
    }
}

#[derive(Debug, Default)]
struct EntryContext {
    expects: CodecExpect,
    headers: HeaderLines,
    time: Option<DateTime>,
    user: Option<SessionLine>,
    stats: Option<StatsLine>,
    set_timestamp: Option<u32>,
    attributes: Option<EntrySqlAttributes>,
}

impl EntryContext {
    fn complete(&mut self) -> Result<Entry, EntryError> {
        let time = self.time.clone().ok_or(MissingField("time".into()))?;
        let session = self.user.clone().ok_or(MissingField("user".into()))?;
        let stats = self.stats.clone().ok_or(MissingField("stats".into()))?;
        let set_timestamp = self
            .set_timestamp
            .clone()
            .ok_or(MissingField("set timestamp".into()))?;
        let attributes = self.attributes.clone().ok_or(MissingField("sql".into()))?;
        let e = Entry {
            call: EntryCall::new(time, set_timestamp),
            session: session.into(),
            stats: stats.into(),
            sql_attributes: attributes,
        };

        self.reset();

        Ok(e)
    }

    fn reset(&mut self) {
        *self = EntryContext::default();
    }
}

/// struct holding contextual information used while decoding
#[derive(Debug, Default)]
pub struct EntryCodec {
    processed: usize,
    context: EntryContext,
    config: EntryCodecConfig,
}

impl EntryCodec {
    /// create a new `EntryCodec` with the specified configuration
    pub fn new(c: EntryCodecConfig) -> Self {
        Self {
            config: c,
            ..Default::default()
        }
    }
    /// calls the appropriate parser based on the current state held in the Codec context
    fn parse_next<'b>(&mut self, i: &mut Stream<'b>) -> ModalResult<Option<Entry>> {
        let entry = match self.context.expects {
            CodecExpect::Header => {
                let _ = multispace0(i)?;

                let res = opt(log_header).parse_next(i)?;
                self.context.expects = CodecExpect::Time;
                self.context.headers = res.unwrap_or_default();

                None
            }
            CodecExpect::Time => {
                let _ = multispace0(i)?;

                let dt = parse_entry_time(i)?;
                self.context.time = Some(dt);
                self.context.expects = CodecExpect::User;
                None
            }
            CodecExpect::User => {
                let sl = entry_user(i)?;
                self.context.user = Some(sl);
                self.context.expects = CodecExpect::Stats;
                None
            }
            CodecExpect::Stats => {
                let _ = multispace0(i)?;
                let st = parse_entry_stats(i)?;
                self.context.stats = Some(st);
                self.context.expects = CodecExpect::UseDatabase;
                None
            }
            CodecExpect::UseDatabase => {
                let _ = multispace0(i)?;
                let _ = opt(use_database).parse_next(i)?;

                self.context.expects = CodecExpect::StartTimeStamp;
                None
            }
            CodecExpect::StartTimeStamp => {
                let _ = multispace0(i)?;
                let st = start_timestamp_command(i)?;
                self.context.set_timestamp = Some(st.into());
                self.context.expects = CodecExpect::Sql;
                None
            }
            CodecExpect::Sql => {
                let _ = multispace0(i)?;

                // ⛔ `opt`, NOT A BARE CALL. winnow rewinds only where a combinator takes a
                // checkpoint; a parser that fails after consuming leaves the stream where it
                // stopped. `admin_command(i)` discarded on `Err` therefore resumed mid-line,
                // and `sql_lines` below read the remainder as the statement -- filing
                // `InvalidStatement("DB;")` for `# administrator command: Init DB;`. `opt`
                // restores the checkpoint on a backtrack and still propagates `Incomplete`,
                // which is what a partial stream needs.
                if let Some(c) = opt(admin_command).parse_next(i)? {
                    self.context.attributes = Some(EntrySqlAttributes {
                        sql: (c.command.clone()),
                        statement: EntryStatement::AdminCommand(c),
                    });
                } else {
                    let mut details = None;

                    if let Ok(Some(d)) = opt(details_comment).parse_next(i) {
                        details = Some(d);
                    }

                    let mut sql_lines = sql_lines(i)?;

                    let s = if let Ok(s) =
                        parse_sql(&String::from_utf8_lossy(&sql_lines), &self.config.masking)
                    {
                        if s.len() == 1 {
                            // ⭐⭐ NO MAPPER NOW CARRIES THE COMMENT THROUGH, RATHER THAN
                            // DISCARDING IT. `map_comment_context` defaults to `None`, and
                            // while `None` meant "drop the context" every consumer taking the
                            // default got four NULL columns and no way to tell that from an
                            // application that annotates nothing. Parsing a comment and then
                            // throwing it away because nobody registered a function is not a
                            // default anybody wants; the hook survives for consumers that want
                            // to filter or reject, and doing nothing yields what was written.
                            let context: Option<SqlStatementContext> =
                                details.and_then(|d| match &self.config.map_comment_context {
                                    Some(f) => f(d),
                                    None => SqlStatementContext::new(d),
                                });

                            let s = EntrySqlStatement {
                                statement: s[0].clone(),
                                context,
                            };

                            sql_lines = Bytes::from(s.statement.to_string());
                            SqlStatement(s)
                        } else {
                            EntryStatement::InvalidStatement(
                                String::from_utf8_lossy(&sql_lines).to_string(),
                            )
                        }
                    } else {
                        EntryStatement::InvalidStatement(
                            String::from_utf8_lossy(&sql_lines).to_string(),
                        )
                    };

                    self.context.attributes = Some(EntrySqlAttributes {
                        sql: sql_lines,
                        //-- TODO: pull this from the Entry Statement
                        statement: s,
                    });
                }

                let e = self.context.complete().unwrap();
                Some(e)
            }
        };

        return if let Some(e) = entry {
            self.processed.add_assign(1);

            Ok(Some(e))
        } else {
            Ok(None)
        };
    }
}

impl Decoder for EntryCodec {
    type Item = Entry;
    type Error = CodecError;

    /// calls `parse_next` and manages state changes and buffer fill
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            // Not enough data to read length marker.
            return Ok(None);
        }

        // Read length marker.
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        // Check that the length is not too large to avoid a denial of
        // service attack where the server runs out of memory.
        if length > LENGTH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            )
            .into());
        }

        let b = &src.split()[..];
        let mut i = Stream::new(&b);

        let mut start = i.checkpoint();

        loop {
            if i.len() == 0 {
                return Ok(None);
            };

            match self.parse_next(&mut i) {
                Ok(e) => {
                    if let Some(e) = e {
                        self.context = EntryContext::default();

                        src.extend_from_slice(i.as_bytes());

                        return Ok(Some(e));
                    } else {
                        debug!("preparing input for next parser\n");

                        start = i.checkpoint();

                        continue;
                    }
                }
                Err(ErrMode::Incomplete(_)) => {
                    i.reset(&start);
                    src.extend_from_slice(i.as_bytes());

                    return Ok(None);
                }
                Err(ErrMode::Backtrack(e)) => {
                    panic!(
                        "unhandled parser backtrack error after {:#?} processed: {}",
                        e.to_string(),
                        self.processed
                    );
                }
                Err(ErrMode::Cut(e)) => {
                    panic!(
                        "unhandled parser cut error after {:#?} processed: {}",
                        e.to_string(),
                        self.processed
                    );
                }
            }
        }
    }

    /// decodes end of file and ensures that there are no unprocessed bytes on the stream.
    ///
    /// and `io::Error` of type io::ErrorKind::Other is thrown in the case of remaining data.
    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                let p = buf.iter().position(|v| !v.is_ascii_whitespace());

                if p.is_none() {
                    Ok(None)
                } else {
                    let out = format!(
                        "bytes remaining on stream; {}",
                        std::str::from_utf8(buf).unwrap()
                    );
                    Err(io::Error::new(io::ErrorKind::Other, out).into())
                }
            }
        }
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
    use std::default::Default;
    use std::io::Cursor;
    use std::collections::HashMap;
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

        // ⭐ NO MAPPER. This test used to register a `map_comment_context` that renamed the
        // comment's keys -- `file` into a field called `caller`, `method` into `function` --
        // and without one the context was dropped entirely. Both are gone: the default now
        // carries the pairs through under the names the comment used.
        let config = EntryCodecConfig::default();

        let mut ff = Framed::new(Cursor::new(&mut eb), EntryCodec::new(config));
        let e = ff.next().await.unwrap().unwrap();

        let stmts = parse_sql(sql, &EntryMasking::None).unwrap();

        let expected_stmt = EntrySqlStatement {
            statement: stmts.get(0).unwrap().clone(),
            context: SqlStatementContext::new(HashMap::from([
                (Bytes::from("request_id"), Bytes::from("apLo5wdqkmKw4W7vGfiBc5")),
                (Bytes::from("file"), Bytes::from("src/endpoints/original/mod.rs")),
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
/*!40101 SET NAMES utf8 */;
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
        assert_eq!(invalid, 1, "valid");
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

    /// ⭐ EVERY `# administrator command:` LINE IS AN `AdminCommand`, INCLUDING THE MULTI-WORD
    /// ONES. `assets/slow-test-queries.log` holds sixteen; before this was fixed, thirteen
    /// survived.
    ///
    /// The three that did not were `Init DB` twice and `Register Slave` once, and they were not
    /// merely misclassified. `admin_command` read the command with `alphanumerichyphen1`, which
    /// cannot match a space, and `codec.rs` called it bare -- winnow leaves the stream where a
    /// failed parser stopped, so `sql_lines` read the remainder and filed
    /// `InvalidStatement("DB;")` / `InvalidStatement("Slave;")`. The command name was destroyed
    /// and a fragment of a comment line was filed as the statement's SQL.
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

    /// ⛔ AND THE OTHER HALF: A FAILED ATTEMPT MUST NOT CONSUME.
    ///
    /// This is the property that turned a classification gap into data corruption. winnow
    /// rewinds only where a combinator takes a checkpoint, so `admin_command(i)` discarded on
    /// `Err` left the stream mid-line. Here the command line has no terminating `;`, so the
    /// parser matches its prefix and then fails -- exactly the shape that used to consume.
    ///
    /// ⚠️ WHAT THIS DOES NOT GUARD, SAID PLAINLY. It pins `opt`'s contract, not the codec's
    /// use of it: revert `admin_command` to the single-word matcher and this still passes,
    /// because the `opt` here restores either way. Only `multi_word_admin_commands_survive`
    /// notices that. Nothing in this file currently fails if somebody drops the `opt` at the
    /// call site while the command parser stays correct -- with both halves in place that
    /// rewind is defence in depth, and the honest thing is to say so rather than claim a
    /// guard that is not there.
    #[test]
    fn a_failed_admin_command_does_not_consume() {
        let input = b"# administrator command: Init DB
SELECT 1;
";
        let mut i: Stream = Partial::new(&input[..]);

        let parsed = opt(admin_command).parse_next(&mut i).unwrap();

        assert!(parsed.is_none(), "no `;`, so this is not a complete command");
        assert_eq!(
            i.as_bytes(),
            &input[..],
            "the stream must be exactly where it started"
        );
    }
}
