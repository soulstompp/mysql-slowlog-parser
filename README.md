# mysql-slowlog-parser - streaming slow query log parser

[![crates.io](https://img.shields.io/crates/v/mysql-slowlog-parser?style=flat-square)](https://crates.io/crates/mysql-slowlog-parser)
[![docs.rs docs](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/winnow-iso8601)

## About

While certainly not the first slowlog parser written, this one attempts to extract a great deal more information than
its predecessors. The parsers extract nearly all the information about each line in an
`Entry` and with plans to extract eventually collect anything missed along the way.

The query found within an entry is also parsed to extract query meta-information about the query (such as which tables
and databases are accessed), what type of query and masking of parameters, primarily to normalize repeated calls of the
same query.

Since it is a fairly common practice to include important information in the comment of a query. So, each of
these comments are parsed to find key-value pairs and include as a Hashmap.

This library is able to read from streams of slow logs from a variety of sources and can handle large logs without
memory issues.

### Usage
The parser is built as a [tokio codec](https://docs.rs/tokio-util/latest/tokio_util/codec/index.html) and so can accept
anything that [FramedRead]() supports.

```rust, ignore
    let fr = FramedRead::with_capacity(
        File::open("mysql-slow-lobsters.log")
            .await
            .unwrap(),
        EntryCodec::default(),
        400000,
    );

    let future = fr.for_each(|re: Result<Entry, CodecError>| async move {
        let _ = re.unwrap();

        // do something here with each entry
    });

    future.await;
```

### Entries
The parsers or codec will return an Entry struct for each object found which contains the following information.
The struct offers several methods to get to this information.

#### Call Information
Information about the start and end time of the query run including the time period it held locks `EntryCall`

#### Session Information
Information about the user connection, contained in `EntrySession`

#### Query Stats
Details on how long and how often the query ran, contained in EntryStats.

#### Query Information
EntrySqlAttributes
Contains information on the query the entry is about. You can find out the following
information about a query:

* The query, with values (depending on settings). At the moment, the values that are masked aren't properly
stored in `EntrySqlAttributes` are lost. This problem will be fixed in an upcoming release.
* An AST of the query if it was parseable by [sql parser](https://crates.io/crates/sqlparser).
* Objects referred to in a parseable query.
* Database schema referred to in a parseable query.
* Key/value pairs from the comment of the query

### Additional Information
In order to understand the data streaming back to you, see [Entry][] which holds information returned from individual
[parsers][`crate::parsers`] in the [docs][docs]

# License

MIT Licensed. See [LICENSE](https://mit-license.org/)

[docs]: https://docs.rs/mysql-slowlog-parser/
