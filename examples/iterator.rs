use futures::StreamExt;
use mysql_slowlog_parser::{CodecError, Entry, EntryCodec};
use std::ops::AddAssign;
use std::time::Instant;
use tokio::fs::File;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() {
    let start = Instant::now();

    let fr = FramedRead::with_capacity(
        File::open("/home/soulstompp/dev/mysql8-stresser/data/mysql-slow-lobsters-normal.log")
            .await
            .unwrap(),
        EntryCodec::default(),
        140000,
    );

    let mut i = 0;

    let future = fr.for_each(|re: Result<Entry, CodecError>| async move {
        let _ = re.unwrap();

        i.add_assign(1);
    });

    future.await;
    println!("parsed {} entries in: {}", i, start.elapsed().as_secs_f64());
}
