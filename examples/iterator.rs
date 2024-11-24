use futures::StreamExt;
use mysql_slowlog_parser::{EntryCodec, EntrySqlType};
use std::collections::HashMap;
use tokio::fs::File;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() {
    let fr = FramedRead::new(
        File::open("assets/slow-test-queries.log").await.unwrap(),
        EntryCodec::default(),
    );

    let future = fr.fold(HashMap::new(), |mut acc, re| async move {
        let entry = re.unwrap();

        match entry.sql_attributes.sql_type() {
            Some(st) => {
                acc.insert(st, acc.get(&st).unwrap_or(&0) + 1);
            }
            None => {
                acc.insert(
                    EntrySqlType::Unknown,
                    acc.get(&EntrySqlType::Unknown).unwrap_or(&0) + 1,
                );
            }
        }

        acc
    });

    let type_counts = future.await;

    for (k, v) in type_counts {
        println!("{}: {}", k, v);
    }
}
