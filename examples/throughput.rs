//! Timing harness: read a log through `FramedRead<EntryCodec>` three ways and report each.
//! Run it with `cargo run --release --example throughput -- <path>...`.
//!
//! The three routes separate the decoder's own cost from the plumbing around it:
//!   `file/8k`  — `tokio::fs::File` with `FramedRead`'s default buffer
//!   `file/64k` — the same, with `FramedRead::with_capacity`
//!   `memory`   — the bytes already in RAM, so the number is the codec alone
use futures::StreamExt;
use mysql_slowlog_parser::EntryCodec;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio_util::codec::FramedRead;

async fn run<R: tokio::io::AsyncRead + Unpin>(r: R, cap: Option<usize>) -> (u64, Duration) {
    let t = Instant::now();
    let mut fr = match cap {
        Some(c) => FramedRead::with_capacity(r, EntryCodec::default(), c),
        None => FramedRead::new(r, EntryCodec::default()),
    };
    let mut n = 0u64;
    while let Some(e) = fr.next().await {
        e.unwrap();
        n += 1;
    }
    (n, t.elapsed())
}

#[tokio::main]
async fn main() {
    for path in std::env::args().skip(1) {
        let bytes = std::fs::metadata(&path).unwrap().len();
        let mem = std::fs::read(&path).unwrap();
        println!("{}  ({} B)", path, bytes);
        // `THROUGHPUT_ONE=1` runs one pass of the first route only, for profiling under
        // callgrind where fifteen passes would just be fifteen copies of the same shape.
        let one = std::env::var("THROUGHPUT_ONE").is_ok();
        let routes: &[(&str, Option<usize>, bool)] = if one {
            &[("file/8k", None, false)]
        } else {
            &[
                ("file/8k", None, false),
                ("file/64k", Some(64 * 1024), false),
                ("memory", None, true),
            ]
        };
        for &(label, cap, in_memory) in routes {
            // best of five, because a first pass pays for page cache and thread pool warm-up
            let mut best = Duration::MAX;
            let mut n = 0;
            for _ in 0..if one { 1 } else { 5 } {
                let (got, d) = if in_memory {
                    run(&mem[..], cap).await
                } else {
                    run(File::open(&path).await.unwrap(), cap).await
                };
                n = got;
                best = best.min(d);
            }
            println!(
                "  {:<9} {:>6} entries  {:>7.1} ms  {:>7.2} MB/s  {:>7.1} ns/byte",
                label,
                n,
                best.as_secs_f64() * 1e3,
                bytes as f64 / 1e6 / best.as_secs_f64(),
                best.as_nanos() as f64 / bytes as f64,
            );
        }
    }
}
