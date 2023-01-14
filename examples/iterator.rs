use mysql_slowlog_parser::{EntryMasking, Reader};
use std::fs::File;
use std::io::BufReader;

fn main() {
    let mut fr = BufReader::new(File::open("data/slow-test-queries.log").unwrap());
    let mut p = Reader::new(&mut fr, EntryMasking::PlaceHolder).unwrap();

    while let Some(e) = p.read_entry().unwrap() {
        println!("{:#?}", e);
    }
}
