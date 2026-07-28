use quant_hft_core::{Sequence, replay_bytes};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const MAX_REPLAY_STREAMS: usize = 4_096;

fn usage(program: &OsString) {
    eprintln!(
        "usage: {} <normalized-journal> [expected-first-capture-ordinal]",
        PathBuf::from(program).display()
    );
}

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("hft-replay"));
    let Some(path) = arguments.next() else {
        usage(&program);
        return ExitCode::from(64);
    };
    let first_capture_ordinal = match arguments.next() {
        None => Sequence(1),
        Some(value) => {
            let Some(text) = value.to_str() else {
                eprintln!("expected-first-capture-ordinal must be UTF-8 decimal");
                return ExitCode::from(64);
            };
            let Ok(parsed) = text.parse::<u64>() else {
                eprintln!("expected-first-capture-ordinal must be an unsigned decimal integer");
                return ExitCode::from(64);
            };
            Sequence(parsed)
        }
    };
    if arguments.next().is_some() {
        usage(&program);
        return ExitCode::from(64);
    }

    let path = PathBuf::from(path);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {error}", path.display());
            return ExitCode::from(66);
        }
    };
    let summary = match replay_bytes::<MAX_REPLAY_STREAMS>(&bytes, first_capture_ordinal) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("replay rejected {}: {error:?}", path.display());
            return ExitCode::from(65);
        }
    };

    println!(
        "records={} streams={} last_capture_ordinal={} last_receive_ns={} capture_digest={:016x}{:016x} consumer_state_digest={:016x}{:016x} outbound_decision_digest={:016x}{:016x}",
        summary.records,
        summary.streams,
        summary.last_capture_ordinal.0,
        summary.last_receive_timestamp.0,
        summary.digest.lane0,
        summary.digest.lane1,
        summary.consumer_state_digest.lane0,
        summary.consumer_state_digest.lane1,
        summary.outbound_decision_digest.lane0,
        summary.outbound_decision_digest.lane1
    );
    ExitCode::SUCCESS
}
