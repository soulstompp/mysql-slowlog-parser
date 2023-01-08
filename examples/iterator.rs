use parse_mysql_slowlog::Reader;

fn main() {
    let mut p = Reader::new("data/slow-test-queries.log").unwrap();

    while let Some(e) = p.read_entry().unwrap() {
        println!("{:#?}", e);
    }
}
