use std::default::Default;
use std::fmt::{Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::AddAssign;
use thiserror::Error;
use time::format_description::well_known::Iso8601;
use tokio_util::codec::Decoder;

use crate::codec::EntryError::MissingField;
use crate::parser::{
    admin_command, details_comment, entry_user, log_header, parse_entry_stats, parse_entry_time,
    parse_sql, sql_lines, start_timestamp_command, use_database, Stream,
};
use crate::types::EntryStatement::SqlStatement;
use crate::types::{Entry, EntryCall, EntrySqlAttributes, EntrySqlStatement, EntryStatement};
use crate::{CodecConfig, SessionLine, SqlStatementContext, StatsLine};
use bytes::{Bytes, BytesMut};
use iso8601::DateTime;
use log::debug;
use time::OffsetDateTime;
use tokio::io;
use winnow::character::multispace0;
use winnow::combinator::opt;
use winnow::error::{ErrMode, Needed};
use winnow::IResult;

#[derive(Error, Debug)]
pub enum EntryError {
    #[error("entry is missing: {0}")]
    MissingField(String),
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("file read error: {0}")]
    IO(#[from] tokio::io::Error),
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
            call: EntryCall::new(
                OffsetDateTime::parse(&time.to_string(), &Iso8601::DEFAULT).unwrap(),
                OffsetDateTime::from_unix_timestamp(set_timestamp as i64).unwrap(),
                stats.query_time,
                stats.lock_time,
            ),
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

#[derive(Debug, Default)]
pub struct EntryCodec {
    processed: usize,
    context: EntryContext,
    config: CodecConfig,
}

impl EntryCodec {
    pub fn new(c: CodecConfig) -> Self {
        Self {
            config: c,
            ..Default::default()
        }
    }
    fn parse_next<'b>(&mut self, i: &'b [u8]) -> IResult<Stream<'b>, Option<Entry>> {
        let mut i = Stream::new(i);

        let (rem, entry) = match self.context.expects {
            CodecExpect::Header => {
                let (i, _) = multispace0(i)?;

                let res = opt(log_header)(i)?;
                self.context.expects = CodecExpect::Time;
                (res.0, None)
            }
            CodecExpect::Time => {
                // the date parser can parse partials as complete, so overfill buffer slightly
                if i.len() < 40 {
                    Err(ErrMode::Incomplete(Needed::Size(
                        NonZeroUsize::try_from(40usize - i.len()).unwrap(),
                    )))?;
                }

                let (i, _) = multispace0(i)?;

                let res = parse_entry_time(i)?;
                self.context.time = Some(res.1);
                self.context.expects = CodecExpect::User;
                (res.0, None)
            }
            CodecExpect::User => {
                let (i, _) = multispace0(i)?;
                let res = entry_user(i)?;
                self.context.user = Some(res.1);
                self.context.expects = CodecExpect::Stats;
                (res.0, None)
            }
            CodecExpect::Stats => {
                let (i, _) = multispace0(i)?;
                let res = parse_entry_stats(i)?;
                self.context.stats = Some(res.1);
                self.context.expects = CodecExpect::UseDatabase;
                (res.0, None)
            }
            CodecExpect::UseDatabase => {
                let (i, _) = multispace0(i)?;
                let res = opt(use_database)(i)?;

                self.context.expects = CodecExpect::StartTimeStamp;
                (res.0, None)
            }
            CodecExpect::StartTimeStamp => {
                let (i, _) = multispace0(i)?;
                let res = start_timestamp_command(i)?;
                self.context.set_timestamp = Some(res.1);
                self.context.expects = CodecExpect::Sql;
                (res.0, None)
            }
            CodecExpect::Sql => {
                let (mut i, _) = multispace0(i)?;

                if let Ok((rem, c)) = admin_command(i) {
                    i = rem;
                    self.context.attributes = Some(EntrySqlAttributes {
                        sql: (c.command.clone()),
                        statement: EntryStatement::AdminCommand(c),
                    });
                } else {
                    let mut details = None;

                    if let Ok((rem, Some(d))) = opt(details_comment)(i) {
                        i = rem;
                        details = Some(d);
                    }

                    let (rem, mut sql_lines) = sql_lines(i)?;
                    i = rem;

                    let s = if let Ok(s) =
                        parse_sql(&String::from_utf8_lossy(&sql_lines), &self.config.masking)
                    {
                        if s.len() == 1 {
                            let context: Option<SqlStatementContext> = if let Some(d) = details {
                                if let Some(f) = &self.config.map_comment_context {
                                    f(d)
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

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
                (i, Some(e))
            }
        };

        i = rem;

        return if let Some(e) = entry {
            self.processed.add_assign(1);

            Ok((i, Some(e)))
        } else {
            Ok((i, None))
        };
    }
}

impl Decoder for EntryCodec {
    type Item = Entry;
    type Error = CodecError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut i = &buf.split()[..];

        if i.len() == 0 {
            return Ok(None);
        };

        loop {
            match self.parse_next(i) {
                Ok((rem, e)) => {
                    if let Some(e) = e {
                        buf.extend_from_slice(*rem);

                        self.context = EntryContext::default();

                        return Ok(Some(e));
                    } else {
                        debug!("preparing input for next parser\n");
                        i = *rem;
                        continue;
                    }
                }
                Err(ErrMode::Incomplete(e)) => {
                    debug!("asking for more data {:?}", e);
                    buf.extend_from_slice(i);
                    return Ok(None);
                }
                Err(ErrMode::Backtrack(e)) | Err(ErrMode::Cut(e)) => {
                    panic!(
                        "unhandled parser error after {:#?} processed: {}",
                        std::str::from_utf8(*e.input).unwrap(),
                        self.processed
                    );
                }
            }
        }
    }

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
    use crate::{CodecConfig, EntryMasking, SqlStatementContext};
    use bytes::{Bytes, BytesMut};
    use futures::StreamExt;
    use std::default::Default;
    use std::io::Cursor;
    use std::ops::AddAssign;
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    use tokio::fs::File;
    use tokio_util::codec::Framed;

    #[tokio::test]
    async fn parses_select_entry() {
        let sql_comment = "-- request_id: apLo5wdqkmKw4W7vGfiBc5 file: src/endpoints/original/mod\
        .rs method: notifications() line: 38";
        let sql = "SELECT film.film_id AS FID, film.title AS title, film.description AS \
        description, category.name AS category, film.rental_rate AS price FROM category LEFT JOIN \
         film_category ON category.category_id = film_category.category_id LEFT JOIN film ON \
         film_category.film_id = film.film_id GROUP BY film.film_id, category.name;";
        //NOTE: decimal places were shortened by parser, so this time is shortened
        let time = "2018-02-05T02:46:47.273Z";
        let set_timestamp = 1517798807;

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

        let config = CodecConfig {
            masking: Default::default(),
            map_comment_context: Some(Box::new(|d| {
                let acc = SqlStatementContext {
                    request_id: d
                        .get(&*BytesMut::from("request_id"))
                        .and_then(|b| Some(b.clone())),
                    caller: d
                        .get(&*BytesMut::from("file"))
                        .and_then(|b| Some(b.clone())),
                    function: d
                        .get(&*BytesMut::from("method"))
                        .and_then(|b| Some(b.clone())),
                    line: d
                        .get(&*BytesMut::from("line"))
                        .and_then(|b| String::from_utf8_lossy(b).parse().ok()),
                };

                if acc == SqlStatementContext::default() {
                    None
                } else {
                    Some(acc)
                }
            })),
        };

        let mut ff = Framed::new(Cursor::new(&mut eb), EntryCodec::new(config));
        let e = ff.next().await.unwrap().unwrap();

        let stmts = parse_sql(sql, &EntryMasking::None).unwrap();

        let expected_stmt = EntrySqlStatement {
            statement: stmts.get(0).unwrap().clone(),
            context: Some(SqlStatementContext {
                request_id: Some("apLo5wdqkmKw4W7vGfiBc5".into()),
                caller: Some("src/endpoints/original/mod.rs".into()),
                function: Some("notifications()".into()),
                line: Some(38),
            }),
        };

        let expected_sql = sql.trim().strip_suffix(";").unwrap();

        let expected_entry = Entry {
            call: EntryCall::new(
                OffsetDateTime::parse(time, &Iso8601::DEFAULT).unwrap(),
                OffsetDateTime::from_unix_timestamp(1517798807 as i64).unwrap(),
                0.000352,
                0.0,
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

        assert_eq!(e.query_start_time().unix_timestamp(), set_timestamp);
    }

    #[tokio::test]
    async fn parses_multiple_entries() {
        let entries = "# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
-- ID: 123 caller: hello_world()
SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT JOIN film ON film_category.film_id = film.film_id
GROUP BY film.film_id, category.name;
# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
/*!40101 SET NAMES utf8 */;
# Time: 2018-02-05T02:46:47.273786Z
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
SET timestamp=1517798807;
-- ID: 456 caller: hello_world()
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
        let f = File::open("data/slow-test-queries.log").await.unwrap();
        let mut ff = Framed::new(f, EntryCodec::default());

        let mut i = 0;

        while let Some(res) = ff.next().await {
            let _ = res.unwrap();
            i.add_assign(1);
        }

        assert_eq!(i, 310);
    }
}
