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
    time: Option<DateTime>,
    user: Option<SessionLine>,
    stats: Option<StatsLine>,
    set_timestamp: Option<u32>,
    use_database: Option<Bytes>,
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

    /// ⛔⛔ `*self = default()` WIPES EVERY FIELD, AND ONE OF THEM WAS NOT AN ENTRY'S.
    ///
    /// The log header is a fact about the FILE — which server wrote it — and it lived in the
    /// per-entry context, so the first completed entry destroyed it. That is a scope error and
    /// not an oversight: a whole-of-file fact in a struct whose contract is "cleared between
    /// entries" cannot survive by any amount of reading it. It lives on the codec now.
    fn reset(&mut self) {
        *self = EntryContext::default();
    }
}

/// struct holding contextual information used while decoding
#[derive(Debug, Default)]
pub struct EntryCodec {
    processed: usize,
    /// ⭐ File-scoped, beside `processed`, because that is its scope. See `EntryContext::reset`.
    headers: Option<HeaderLines>,
    /// ⭐⭐ How many header blocks the file carried. See [`EntryCodec::header_count`].
    headers_seen: usize,
    context: EntryContext,
    config: EntryCodecConfig,
}

impl EntryCodec {
    /// ⭐ The header lines the file opened with, or `None` where it had none.
    ///
    /// Valid once the first entry has been decoded; a caller holding a `FramedRead` reaches it
    /// through `decoder()`. ⛔ `None` is `unmeasured` and never "the default server": a slow log
    /// that has been rotated or concatenated begins mid-stream and states no regime at all.
    pub fn headers(&self) -> Option<&HeaderLines> {
        self.headers.as_ref()
    }

    /// ⭐⭐ How many header blocks the file carried, which is how many servers claimed it.
    ///
    /// ⛔ More than one means the file is a CONCATENATION and its regime is not one thing. The
    /// entries before the second header were written by one server and those after it by
    /// another, and nothing else in any artifact would distinguish them. [`EntryCodec::headers`]
    /// returns the first; this says whether "the first" is also "the only".
    pub fn header_count(&self) -> usize {
        self.headers_seen
    }

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
                // ⛔ `Option`, NOT `unwrap_or_default`. A log with no header and a log whose
                // header carried an empty version were the same value, so the one thing that
                // states the server's regime could not be told from its own absence — and a
                // rotated or concatenated slow log genuinely has no header.
                //
                // ⛔⛔ AND IT MUST NOT BE AN ASSIGNMENT, WHICH IS WHAT IT WAS. `decode` resets
                // the context after every completed entry, so `expects` returns to `Header` and
                // this arm runs again between EVERY pair of entries. A plain `self.headers =
                // res` therefore set the version once and then overwrote it with `None` 309
                // times. It survived a test that read one entry and vanished on any real file.
                //
                // ⭐ That the arm runs repeatedly is not a defect: a slow log can be rotated and
                // concatenated, and a second header block mid-file means the rest of the entries
                // were written by a different server. The FIRST is kept and the COUNT is
                // recorded, so a file that declares two regimes says so rather than quietly
                // presenting one.
                if let Some(h) = res {
                    self.headers_seen += 1;
                    if self.headers.is_none() {
                        self.headers = Some(h);
                    }
                }

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
                // ⛔⛔ THIS WAS `let _ =`. The author said which schema every unqualified
                // relation in the entry belongs to, the parser read it, and the codec threw it
                // on the floor -- so `film` filed with no schema while the log said
                // `use sakila;` two lines earlier.
                //
                // ⚠️ AND IT IS FILED ONLY WHERE THE LOG SAID IT. `USE` is sticky per connection
                // and MySQL writes it when the database CHANGES, so later entries on the same
                // thread inherit a database this entry never mentions. Carrying it forward is a
                // reader's inference over the thread, and it belongs to whoever draws it.
                self.context.use_database = opt(use_database).parse_next(i)?;

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
                        // ⚠️ `None`, because a different parser consumed the line and its
                        // framing. `sql` above is still the log's own bytes here -- the command
                        // word -- so nothing is lost; there is simply no *statement* text to
                        // file. `statement_kind` says which rows these are.
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

                    // ⭐⭐ THE AUTHOR'S OWN BYTES, KEPT. `Bytes` is refcounted, so this costs an
                    // atomic increment and no copy -- and without it line ~230 below overwrites
                    // the only surviving record of what the author wrote. That reassignment made
                    // PARSE SUCCESS the thing that destroys the document: the 131 statements
                    // nobody could read keep their text, and the 163 that parsed do not.
                    //
                    // ⭐ It also carries every literal as text even when masking is on, because
                    // masking happens inside `parse_sql` and touches only the tree.
                    let sql_raw = sql_lines.clone();
                    let mut literals = Vec::new();

                    let s = if let Ok((s, ls)) =
                        parse_sql(&String::from_utf8_lossy(&sql_lines), &self.config.masking)
                    {
                        literals = ls;
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
                        sql_raw: Some(sql_raw),
                        literals,
                        use_database: self.context.use_database.clone(),
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
            statement: stmts.0.first().unwrap().clone(),
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
                sql_raw: Some(sql.trim().into()),
                literals: vec![],
                // ⭐ The fixture entry is preceded by `use mysql;`, and until this commit the
                // codec bound that to `_`. The author said which schema their unqualified
                // relations live in and the record threw it away.
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

/// The relation graph, measured over every statement in the shipped log rather than over
/// hand-written SQL.
///
/// ⭐ THIS IS THE REGRESSION CORPUS AND NOT MUCH ELSE. The log is a sandbox startup and a
/// `mysqldump` restore, so its structural content and its performance content are disjoint: every
/// statement that names more than one relation is a `CREATE VIEW` that ran once, examined no rows
/// and took no locks. What it can prove is that the walk over 163 real parses loses nothing
/// `objects()` held, and that the one interesting shape in it is found.
#[cfg(test)]
mod graph_census {
    use crate::codec::EntryCodec;
    use crate::{EntryStatement, RelationRole, ScopeKind};
    use std::ops::Not;
    use futures::StreamExt;
    use std::ops::AddAssign;
    use tokio::fs::File;
    use tokio_util::codec::Framed;

    /// ⭐⭐⭐ THE REGIME THE FILE DECLARES, WHICH NOTHING HAS EVER READ.
    ///
    /// Every claim a reader makes about MySQL's *behaviour* holds in a regime, and the first
    /// line of a slow log is the only place the document names one. This corpus says **5.7.20**;
    /// the structural fixture next door says 8.0.35. A filing that asserts one lock model across
    /// both is asserting it across two servers that do not agree — online DDL, atomic DDL and
    /// `ALGORITHM=INSTANT` all change which statements block which, for identical statement text.
    ///
    /// ⛔ And it must be an `Option`. `opt(log_header)` fed `unwrap_or_default()`, so a log with
    /// no header at all — a rotated or concatenated one, which begins mid-stream — was
    /// indistinguishable from a header whose version was empty. The regime and its own absence
    /// were one value.
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

        // ⚠️ UNPARSED ON PURPOSE. Splitting this into numbers is a reading, and `-log` here,
        // `-MariaDB` elsewhere and `-percona` elsewhere again are three different grammars for
        // the same field. Whoever needs a comparison makes it, on the bytes the server wrote.
        assert!(h.version().as_ref().starts_with(b"5.7."));

        // ⛔⛔ AND IT MUST SURVIVE THE WHOLE FILE, WHICH IT DID NOT. `decode` resets the context
        // after every completed entry, so `expects` returns to `Header` and the header arm runs
        // between EVERY pair of entries; a plain assignment set the version once and then
        // overwrote it with `None` 309 times. A test that read one entry passed and every real
        // file came out with no regime at all. Drain the stream and ask again.
        while (ff.next().await).is_some() {}
        let h = ff.codec().headers().expect("the regime is a fact about the FILE");
        assert!(h.version().as_ref().starts_with(b"5.7."));

        // ⭐ ONE HEADER, SO "THE FIRST" IS ALSO "THE ONLY". A rotated and concatenated log
        // carries several, and its entries were then written by more than one server — which
        // nothing else in any artifact would distinguish.
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
            // ⛔ Nothing `objects()` found may be missing from the graph. The reverse is
            // allowed and is the point: the graph finds the view being created, which
            // `objects()` cannot.
            //
            // ⛔⛔ AND THE COMPARISON HAS TO STRIP BACKTICKS, WHICH IS ITSELF A DEFECT.
            // `ObjectNamePart`'s `Display` renders the quote style and `objects()` builds its
            // names with `to_string()`, so `` `actor` `` and `actor` come out as two different
            // relations. `PLAN-2026-09-22-02-fusion.md:161` records exactly that as measured
            // data -- ``actor -> ['`actor`', 'actor', 'sakila.actor']`` -- and files all three
            // under a reader's mapping of spellings onto tables. One of the three is not a
            // spelling difference at all. The parse has carried the unquoted value the whole
            // time; only the accessor threw it away.
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
        // ⛔ ONE MISS IN 163 STATEMENTS, AND IT IS NOT A RELATION. `SHOW TABLES FROM mysql` names
        // a SCHEMA, and `ShowStatementIn.parent_name` carries a `visit_relation` annotation, so
        // `objects()` files the schema `mysql` as though it were a table. The graph declines to,
        // which is why this is an exception with an argument rather than a gap to close.
        assert_eq!(
            missed,
            vec!["mysql <- ShowTables".to_string()],
            "the graph may hold more than objects(), and may lose nothing that is a relation"
        );

        assert_eq!(parsed, 310);
        assert_eq!(with_graph, 163, "statements with an AST to walk");

        // ⭐ The seven `CREATE VIEW`s are the whole of this log's structure, and all 39 relations
        // they mention sit in a view body -- NAMED, never read. `PLAN-2026-09-22-02-fusion.md`
        // measures an elimination of 1.80% against `query_time` over exactly these statements and
        // says at :128 that "every k >= 2 statement in this fixture is a CREATE VIEW". The flat
        // `objects` set cannot tell a table scanned from a table named in a DDL body, so that
        // 1.80% is drawn entirely from statements that touched none of the tables it weights.
        assert_eq!(view_bodies, 7, "every multi-relation statement is a view");
        assert_eq!(named_only, 39, "relations named in a body, not scanned");

        // ⭐⭐ ONE non-tree descent in 163 statements, and it is `actor_info`: its correlated
        // subquery rebinds `fa` and `fc`, and the two correlation edges close a cycle.
        // `rank/composition_closure.sqlc` computes a kernel two ways and says they "agree
        // exactly where the descent is a tree"; every layer graph in that corpus is a forest, so
        // the disagreeing case has never had a witness. This is one. A population of one is thin
        // and it is not zero, which is the difference between a law that is suspended and a law
        // that is vacuous.
        assert_eq!(non_tree, 1, "actor_info, and nothing else");

        // ⛔⛔ TEN OF THESE DID NOT EXIST, AND THEY ARE THE ONLY DDL IN THIS LOG THAT CAN BLOCK
        // A READER. `demand.parquet` separates `ddl` from `write` because a DDL takes
        // `MDL_EXCLUSIVE`; until this walk the role was reachable only by `CREATE VIEW` and
        // `CREATE TABLE`, which name a relation that did not exist and block nobody.
        //
        // ⚠️ AND THE ALTERS ARE ZERO, WHICH IS THE SHARPER HALF. This log holds 32
        // `ALTER TABLE`s and every one of them says `DISABLE KEYS` or `ENABLE KEYS` — a MySQL
        // form `sqlparser` refuses outright, so those entries are `invalid`, carry no AST and
        // reach no graph at all. The statement that takes `MDL_EXCLUSIVE` on a live table is
        // invisible here twice over, and filing the role does not change that. `AlterTarget`
        // has its witness in the other corpus; the bound is stated rather than inferred.
        //
        // ⚠️ 10 drops against 11 `DROP` lines: `DROP DATABASE IF EXISTS sakila` names a schema
        // and not a relation, and the walk declines it for the same reason the census's one
        // permitted `objects()` miss is `SHOW TABLES FROM mysql`.
        assert_eq!((altered, dropped), (0, 10), "the DDL that names an existing table");
        // ⭐⭐⭐ AND SIXTEEN OF THEM ARE THE LOCK THIS LOG'S OWN `Lock_time` COLUMN MEASURES THE
        // WAIT FOR. `mysqldump` writes `LOCK TABLES `t` WRITE` before each table's inserts, so a
        // restore is a sequence of explicit table locks — and `LockTables.tables` carries no
        // `visit_relation` annotation, so every one of them was absent from `objects()` and from
        // every artifact downstream of it. The statement that TAKES the lock and the column that
        // measures the WAIT have never been in the same record.
        //
        // ⛔⛔ AND ZERO ANALYZED, THOUGH THIS LOG RUNS AN `ANALYZE TABLE` OVER SIXTEEN TABLES.
        // MySQL's `ANALYZE TABLE` takes a LIST; `sqlparser`'s `Analyze` carries a single
        // `table_name`, so the multi-table form is refused outright and the entry is `invalid`.
        //
        // ⭐⭐ THAT IS A SECOND REGIME AND THIS FILING KEPT CONFLATING IT WITH THE FIRST. What
        // the SERVER can do is one question — it ran the statement, that is why the line is in
        // the log — and what this GRAMMAR can read is another. `ALTER TABLE … DISABLE KEYS`,
        // `ANALYZE TABLE a, b`, `OPTIMIZE TABLE`, `DROP INDEX … ON t` and
        // `LOCK TABLES shop.invoice WRITE` are all valid MySQL and all refused here. A role with
        // no witness in a corpus may be a role the corpus never exercised OR a grammar that
        // cannot read the corpus, and only naming both regimes tells them apart.
        assert_eq!((lock_x, lock_s, analyzed), (16, 0, 0));
        assert_eq!(occurrences, 147);
        assert_eq!(edges, 33);

        // ⛔ The seven views this log creates are invisible to `objects()` -- `CreateView.name`
        // carries no `visit_relation` annotation while `CreateTable.name` does -- so a reader
        // asking which relations a `CREATE VIEW` statement concerns gets its sources and never
        // the thing it defines.
        assert_eq!(view_targets, 7);

        // ⭐ And the quoting defect, sized: 46 names `objects()` reports wrapped in backticks and
        // the graph reports bare.
        assert_eq!(quoted, 46, "names objects() spells with backticks");
    }
}

/// ⭐⭐ WHAT THE AUTHOR WROTE, AGAINST WHAT THE READER MADE OF IT.
///
/// `EntrySqlAttributes::sql` is the AST rendered back to text on every statement that parsed, so
/// until `sql_raw` existed **parse success was the thing that destroyed the document**: the 131
/// statements nobody could read kept their bytes and the 163 that parsed did not.
#[cfg(test)]
mod the_author_and_the_reader {
    use crate::codec::EntryCodec;
    use crate::{EntryStatement, LiteralKind};
    use futures::StreamExt;
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
                        a.sql_raw.as_ref().expect("a parsed statement has raw bytes"),
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
                // ⚠️ An administrator command has no statement text: a different parser consumed
                // the line and its framing. `sql` there is still the log's own bytes.
                EntryStatement::AdminCommand(_) => assert!(a.sql_raw.is_none()),
                // ⭐ And an unparseable statement kept its bytes all along -- which is the
                // inversion this commit is about.
                EntryStatement::InvalidStatement(_) => assert!(a.sql_raw.is_some()),
            }
        }

        assert_eq!((n, parsed), (310, 163));

        // ⭐⭐ SIXTY-ONE PER CENT OF THE PARSED STATEMENTS ARE NOT WHAT THE AUTHOR WROTE, and
        // that column is what a consumer's coarsening ladder calls its byte-identity floor.
        assert_eq!(differs, 99);
        assert_eq!(newlines_lost, 59, "multi-line statements flattened to one");
        assert_eq!(lowercase, 9, "keywords the author did not capitalise");

        // ⭐ The author's subject, recovered -- and recovered whether or not masking is on,
        // because the bytes carry it even when the tree does not.
        assert_eq!(literals, 302);
        assert_eq!(entries_with_literals, 80);
        assert_eq!(kinds.get(&LiteralKind::Number), Some(&98));
        assert_eq!(kinds.get(&LiteralKind::SingleQuotedString), Some(&204));

        // ⚠️ Thin, and not zero. `USE` is written only when the database CHANGES, so two
        // statements in this log carry one and 308 inherit it -- an inference this crate
        // declines to draw. Before this commit the answer was 0, by `let _ =`.
        assert_eq!(with_db, 2);
    }
}
