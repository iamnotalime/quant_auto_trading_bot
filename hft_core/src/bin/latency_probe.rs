use quant_hft_core::{
    BookEvent, L3Book, LatencyHistogram, OrderId, PriceTicks, Quantity, Sequence, Side,
};
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

const WARMUP_EVENTS: u64 = 100_000;
const MEASURED_EVENTS: u64 = 1_000_000;

fn apply_replace(
    book: &mut L3Book<1_024, 256>,
    sequence: u64,
    quantity: i64,
) -> Result<(), quant_hft_core::BookError> {
    black_box(book.apply(
        Sequence(sequence),
        BookEvent::Modify {
            order_id: OrderId(1),
            price: PriceTicks(100_000),
            quantity: Quantity(quantity),
        },
    ))?;
    Ok(())
}

fn main() -> ExitCode {
    if cfg!(debug_assertions) {
        eprintln!("latency-probe must be built with --release; debug timings are invalid");
        return ExitCode::from(64);
    }

    let mut book = L3Book::<1_024, 256>::new(Sequence(1));
    if let Err(error) = book.apply(
        Sequence(1),
        BookEvent::Add {
            order_id: OrderId(1),
            side: Side::Buy,
            price: PriceTicks(100_000),
            quantity: Quantity(10),
        },
    ) {
        eprintln!("book initialization failed: {error:?}");
        return ExitCode::FAILURE;
    }

    for offset in 0..WARMUP_EVENTS {
        let quantity = i64::try_from(offset % 100 + 1).expect("bounded warmup quantity");
        if let Err(error) = apply_replace(&mut book, offset + 2, quantity) {
            eprintln!("warmup failed: {error:?}");
            return ExitCode::FAILURE;
        }
    }

    let mut histogram = LatencyHistogram::<64>::new();
    let first_sequence = WARMUP_EVENTS + 2;
    let batch_start = Instant::now();
    for offset in 0..MEASURED_EVENTS {
        let quantity = i64::try_from(offset % 100 + 1).expect("bounded measured quantity");
        let started = Instant::now();
        if let Err(error) = apply_replace(&mut book, first_sequence + offset, quantity) {
            eprintln!("measurement failed: {error:?}");
            return ExitCode::FAILURE;
        }
        let elapsed = started.elapsed().as_nanos();
        histogram.record(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    let batch_elapsed = batch_start.elapsed().as_nanos();
    let mean_batch_ns = batch_elapsed / u128::from(MEASURED_EVENTS);

    println!(
        "events={} batch_mean_ns={} sampled_mean_ns={} min_ns={} p50_upper_ns={} p99_upper_ns={} p999_upper_ns={} max_ns={}",
        histogram.count(),
        mean_batch_ns,
        histogram.mean_ns().unwrap_or(0),
        histogram.minimum_ns().unwrap_or(0),
        histogram.percentile_upper_bound_ns(50, 100).unwrap_or(0),
        histogram.percentile_upper_bound_ns(99, 100).unwrap_or(0),
        histogram.percentile_upper_bound_ns(999, 1_000).unwrap_or(0),
        histogram.maximum_ns().unwrap_or(0),
    );
    ExitCode::SUCCESS
}
