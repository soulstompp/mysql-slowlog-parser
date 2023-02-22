use mysql_slowlog_parser::Reader;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let mut fr = BufReader::new(File::open("data/slow-test-queries.log").unwrap());

    let rb = Reader::builder().reader(&mut fr);
    let mut r = rb.build().unwrap();

    while let Some(e) = r.read_entry().unwrap() {
        println!("{:#?}", e);
    }
}
