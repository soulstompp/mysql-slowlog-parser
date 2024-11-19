use futures::StreamExt;
use mysql_slowlog_parser::{CodecError, Entry, EntryCodec};
use tokio::fs::File;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() {
    let fr = FramedRead::with_capacity(
        File::open("assets/slow-test-queries.log")
            .await
            .unwrap(),
        EntryCodec::default(),
        400000,
    );

    let future = fr.for_each(|re: Result<Entry, CodecError>| async move {
        let entry = re.unwrap();

        let sql_type = entry.sql_attributes.sql_type();
        
        if sql_type.is_none() {
            return;
        }
        
        let sql_type = match entry.sql_attributes.sql_type() {
            Some(sql_type) => sql_type.to_string(),
            None => String::from("NULL"),
        };
        
        println!("{}: {}", entry.query_start_time(), sql_type);
    });

    future.await;
}
