use futures::StreamExt;
use mysql_slowlog_parser::{EntryCodec, EntryStatement};
use std::collections::BTreeMap;
use tokio::fs::File;
use tokio_util::codec::FramedRead;

/// Counts the entries of a log by the kind of statement each one holds.
#[tokio::main]
async fn main() {
    let fr = FramedRead::new(
        File::open("assets/slow-test-queries.log").await.unwrap(),
        EntryCodec::default(),
    );

    let counts = fr
        .fold(BTreeMap::new(), |mut acc, re| async move {
            let entry = re.unwrap();

            let kind = match &entry.sql_attributes.statement {
                EntryStatement::SqlStatement(s) => s.sql_type().to_string(),
                EntryStatement::AdminCommand(_) => "administrator command".to_string(),
                EntryStatement::InvalidStatement(_) => "refused by the grammar".to_string(),
                _ => "other".to_string(),
            };
            *acc.entry(kind).or_insert(0) += 1;

            acc
        })
        .await;

    for (kind, count) in counts {
        println!("{kind}: {count}");
    }
}
