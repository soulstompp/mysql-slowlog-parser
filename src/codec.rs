use std::fmt::{Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::AddAssign;
use thiserror::Error;
use tokio_util::codec::Decoder;

use crate::codec::EntryError::MissingField;
use crate::parser::{
    admin_command, details_comment, entry_user, log_header, parse_entry_stats, parse_entry_time,
    parse_sql, sql_lines, start_timestamp_command, use_database, Stream,
};
use crate::EntryStatement::SqlStatement;
use crate::{
    Entry, EntrySqlStatement, EntryStatement, EntryStats, EntryTime, EntryUser, ReaderConfig,
    SqlStatementContext,
};
use bytes::{Bytes, BytesMut};
use log::debug;
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
    time: Option<EntryTime>,
    user: Option<EntryUser>,
    stats: Option<EntryStats>,
    set_timestamp: Option<u32>,
    statement: Option<EntryStatement>,
}

impl EntryContext {
    fn complete(&mut self) -> Result<Entry, EntryError> {
        let time = self.time.clone().ok_or(MissingField("time".into()))?;
        let user = self.user.clone().ok_or(MissingField("user".into()))?;
        let stats = self.stats.clone().ok_or(MissingField("stats".into()))?;
        let set_timestamp = self
            .set_timestamp
            .clone()
            .ok_or(MissingField("set timestamp".into()))?;
        let statement = self.statement.clone().ok_or(MissingField("sql".into()))?;
        let e = Entry {
            time: time.time(),
            start_timestamp: set_timestamp,
            user: user.user(),
            sys_user: user.sys_user(),
            host: user.host(),
            ip_address: user.ip_address(),
            thread_id: user.thread_id(),
            query_time: stats.query_time(),
            lock_time: stats.lock_time(),
            rows_sent: stats.rows_sent(),
            rows_examined: stats.rows_examined(),
            statement,
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
    config: ReaderConfig,
}

impl EntryCodec {
    fn parse_next<'b>(&mut self, i: &'b [u8]) -> IResult<Stream<'b>,
        Option<Entry>> {
        let mut i = Stream::new(i);

        let s = (i.len()).min(800);
        debug!(
            "expecting {} from: \n{}",
            self.context.expects,
            std::str::from_utf8(&i[..s]).unwrap()
        );

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
                    self.context.statement = Some(EntryStatement::AdminCommand(c));
                } else {
                    let mut details = None;

                    if let Ok((rem, Some(d))) = opt(details_comment)(i) {
                        i = rem;
                        details = Some(d);
                    }

                    let (rem, sql_lines) = sql_lines(i)?;
                    i = rem;

                    let s = if let Ok(s) = parse_sql(&String::from_utf8_lossy(&sql_lines),
                                                     &self.config
                        .masking) {
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

                            SqlStatement(s)
                        } else {
                            EntryStatement::InvalidStatement(String::from_utf8_lossy(&sql_lines)
                                .to_string())
                        }
                    } else {
                        EntryStatement::InvalidStatement(String::from_utf8_lossy(&sql_lines).to_string())
                    };

                    self.context.statement = Some(s);
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
    use crate::EntryStatement::SqlStatement;
    use crate::{Entry, EntryMasking, EntrySqlStatement, EntrySqlStatementObject, EntryStatement};
    use futures::StreamExt;
    use iso8601::datetime;
    use std::default::Default;
    use std::io::Cursor;
    use std::ops::AddAssign;
    use bytes::Bytes;
    use tokio::fs::File;
    use tokio_util::codec::Framed;

    #[tokio::test]
    async fn parses_select_entry() {
        let sql = "-- ID: 123 caller: hello_world()
        SELECT film.film_id AS FID, film.title AS title, film.description AS description, category.name AS category, film.rental_rate AS price
        FROM category LEFT JOIN film_category ON category.category_id = film_category.category_id LEFT JOIN film ON film_category.film_id = film.film_id
        GROUP BY film.film_id, category.name;";
        let time = "2018-02-05T02:46:47.273786Z";
        let entry = format!(
            "# Time: {}
# User@Host: msandbox[msandbox] @ localhost []  Id:    10
# Query_time: 0.000352  Lock_time: 0.000000 Rows_sent: 0  Rows_examined: 0
use mysql;
SET timestamp=1517798807;
{}
",
            time, sql
        );

        let mut eb = entry.as_bytes().to_vec();

        let mut ff = Framed::new(Cursor::new(&mut eb), EntryCodec::default());
        let e = ff.next().await.unwrap().unwrap();

        let stmts = parse_sql(sql, &EntryMasking::None).unwrap();

        let expected_stmt = EntrySqlStatement {
            statement: stmts.get(0).unwrap().clone(),
            context: None,
        };

        assert_eq!(
            e,
            Entry {
                time: datetime(time).unwrap(),
                start_timestamp: 1517798807,
                user: Bytes::from("msandbox"),
                sys_user: Bytes::from("msandbox"),
                host: Some(Bytes::from("localhost")),
                ip_address: None,
                thread_id: 10,
                query_time: 0.000352,
                lock_time: 0.0,
                rows_sent: 0,
                rows_examined: 0,
                statement: SqlStatement(expected_stmt),
            }
        )
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

            if let EntryStatement::InvalidStatement(_) = e.statement {
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

        match e.statement() {
            SqlStatement(s) => {
                assert_eq!(s.objects(), expected);
                assert_eq!(s.entry_sql_type().to_string(), "SELECT".to_string());
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
