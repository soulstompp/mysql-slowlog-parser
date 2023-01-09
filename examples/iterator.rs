use parse_mysql_slowlog::{EntryMasking, Reader};
use std::fs::File;

fn main() {
    let mut f = File::open("data/slow-test-queries.log").unwrap();
    let mut p = Reader::new(&mut f, EntryMasking::PlaceHolder).unwrap();

    while let Some(e) = p.read_entry().unwrap() {
        println!("{:#?}", e);
    }
}
