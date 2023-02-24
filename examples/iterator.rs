use futures::StreamExt;
use mysql_slowlog_parser::Reader;
use tokio::fs::File;
use tokio::io::BufReader;

#[tokio::main]
async fn main() {
    let mut fr = BufReader::new(File::open("data/slow-test-queries.log").await.unwrap());
    let rb = Reader::builder().reader(&mut fr);
    let mut r = rb.build().unwrap();

    let s = r.read_entries();

    let mut s = Box::pin(s);

    while let Some(re) = s.next().await {
        let e = re.unwrap();

        println!("{:#?}", e);
    }
}
