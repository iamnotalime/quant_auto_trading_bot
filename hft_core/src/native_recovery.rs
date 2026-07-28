//! Non-authorizing inspection of authenticated native-live recovery metadata.
//!
//! This module deliberately does not reconstruct a reactor, venue session, adapter,
//! transport, control gate, or [`crate::native_live::NativeLiveCoordinator`]. It
//! consumes a fully authenticated and externally freshness-anchored container and
//! returns evidence describing which stronger recovery action is still required.
//!
//! The currently supported history is intentionally narrow: exactly one final
//! [`AuditRecordKind::LIVE_CHECKPOINT`] containing a canonical checkpoint payload.
//! Other retained fact types require their own canonical codecs and semantic replay
//! before this scanner may accept them. A native intent is always classified as
//! unfinished by this version, even if an unverified outer disposition kind follows.
//! This is also a single-container scanner: it rejects every header that names a
//! predecessor. A valid predecessor seal authenticates that container's bytes, but
//! does not prove to this API that semantic replay closed every prior ticket or intent.
//!
//! [`VerifiedAuditContainer`] exists only after a terminal container seal has matched
//! an independently retained latest anchor. Consequently, this scanner cannot observe
//! a process-crash tail that ended after an intent but before that seal. Production
//! crash recovery still requires either per-ticket terminal sealing or a separately
//! authenticated committed-prefix protocol that preserves the uncertain intent tail.

use crate::audit_container::{
    AuditAnchor, AuditContainerHeader, AuditContainerId, AuditRecordKind, VerifiedAuditContainer,
};
use crate::events::CaptureOrdinal;
use crate::native_audit_codec::{NativeAuditCodecError, decode_native_live_checkpoint_record};
use crate::native_live::{NativeLiveCheckpoint, NativeLivePhase};

/// A runnable phase observed only as retained metadata.
///
/// Every variant still requires a future owned, typed replay. It is not permission
/// to construct or resume a live coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveRecordedRunnablePhase {
    Ready,
    SafetyPending,
    KilledRecovery,
}

/// A terminal phase that permits evidence inspection and manual reconciliation only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveRecordedNonRunnablePhase {
    Ambiguous,
    Failed,
}

/// Stronger action required after the narrow authenticated scan succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveRecoveryRequirement {
    /// Complete authenticated replay must return all exact runtime owners before use.
    OwnedReplayRequired(NativeLiveRecordedRunnablePhase),
    /// No automatic runtime reconstruction is permitted.
    ManualReconciliation(NativeLiveRecordedNonRunnablePhase),
}

/// Authenticated coordinator metadata that has not authorized a runtime.
///
/// `recorded_checkpoint` remains evidence only. In particular, an observed `Ready`
/// phase is represented by [`NativeLiveRecoveryRequirement::OwnedReplayRequired`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveRecoveryEvidence {
    pub header: AuditContainerHeader,
    pub anchor: AuditAnchor,
    pub scope_ticket: u64,
    pub checkpoint_record_ordinal: u64,
    pub recorded_checkpoint: NativeLiveCheckpoint,
    pub requirement: NativeLiveRecoveryRequirement,
}

/// Authenticated header field contradicted by the checkpoint payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveCheckpointHeaderField {
    VenueIdentity,
    InstrumentDefinitionBinding,
    MarketDataSource,
    OrderEntrySource,
    DropCopySource,
    MonotonicClockEpoch,
}

/// Semantic checkpoint defect that does not require a runtime owner to detect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveRecoveryCheckpointError {
    HeaderMismatch(NativeLiveCheckpointHeaderField),
    InvalidExpectedFirstSourceCapture(CaptureOrdinal),
    InvalidLastSourceCapture {
        expected_at_least: CaptureOrdinal,
        actual: CaptureOrdinal,
    },
    InvalidLastOutboundFrame(u64),
    InvalidNextCommitOrdinal(u64),
}

/// Classification of a record found after the only permitted checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveTrailingRecordKind {
    KnownUnsupported(AuditRecordKind),
    Unknown(u16),
}

/// Exact fail-closed rejection from the non-authorizing scanner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveRecoveryScanError {
    /// The authenticated header continues a container chain whose prior semantic
    /// closure has not been replayed by this single-container scanner.
    PredecessorHistoryUnverified {
        current_generation: u64,
        predecessor_container_id: AuditContainerId,
        predecessor_generation: u64,
    },
    MissingCheckpoint,
    MultipleCheckpoints {
        first_ordinal: u64,
        second_ordinal: u64,
    },
    CheckpointNotFinal {
        checkpoint_ordinal: u64,
        following_ordinal: u64,
        following_kind: NativeLiveTrailingRecordKind,
    },
    /// This scanner has no canonical intent/disposition codec with which to prove
    /// resolution, so every retained intent remains uncertain.
    UnfinishedIntent {
        record_ordinal: u64,
    },
    UnsupportedRecord {
        record_ordinal: u64,
        kind: AuditRecordKind,
    },
    UnknownRecordKind {
        record_ordinal: u64,
        kind: u16,
    },
    CheckpointPayload {
        record_ordinal: u64,
        error: NativeAuditCodecError,
    },
    InvalidCheckpoint {
        record_ordinal: u64,
        error: NativeLiveRecoveryCheckpointError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedCheckpoint {
    scope_ticket: u64,
    record_ordinal: u64,
    checkpoint: NativeLiveCheckpoint,
}

/// Inspect one fully verified container without authorizing live execution.
///
/// The container is consumed by value so the authenticated view itself cannot be
/// reused accidentally after this decision boundary. The returned value owns only
/// fixed-size evidence and this function performs no allocation.
///
/// This API is not an unsealed-prefix verifier. An intent stranded after the latest
/// terminal seal cannot reach this function through [`VerifiedAuditContainer`].
/// It also accepts no caller assertion that a predecessor was semantically closed;
/// a header carrying a predecessor is rejected before any local record is inspected.
///
/// # Errors
///
/// Returns the first unsupported or invalid history fact, except that any native
/// intent anywhere in the container takes precedence as an unfinished-intent safety
/// result. Exactly one valid checkpoint must be the final and only record.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the recovery decision boundary deliberately consumes the verified capability"
)]
pub fn scan_native_live_recovery(
    container: VerifiedAuditContainer<'_>,
) -> Result<NativeLiveRecoveryEvidence, NativeLiveRecoveryScanError> {
    let header = *container.header();
    reject_unverified_predecessor(&header)?;
    let anchor = container.anchor();
    let mut checkpoint_ordinal: Option<u64> = None;
    let mut decoded_checkpoint: Option<DecodedCheckpoint> = None;
    let mut first_error: Option<NativeLiveRecoveryScanError> = None;
    let mut unfinished_intent: Option<u64> = None;

    for record in container.records() {
        if record.kind == AuditRecordKind::NATIVE_INTENT {
            if unfinished_intent.is_none() {
                unfinished_intent = Some(record.ordinal);
            }
            continue;
        }

        if record.kind == AuditRecordKind::LIVE_CHECKPOINT {
            if let Some(first_ordinal) = checkpoint_ordinal {
                set_first_error(
                    &mut first_error,
                    NativeLiveRecoveryScanError::MultipleCheckpoints {
                        first_ordinal,
                        second_ordinal: record.ordinal,
                    },
                );
                continue;
            }
            checkpoint_ordinal = Some(record.ordinal);

            match decode_native_live_checkpoint_record(record.payload) {
                Ok((scope_ticket, decoded)) => {
                    if let Err(error) = validate_checkpoint_against_header(&header, decoded) {
                        set_first_error(
                            &mut first_error,
                            NativeLiveRecoveryScanError::InvalidCheckpoint {
                                record_ordinal: record.ordinal,
                                error,
                            },
                        );
                    }
                    decoded_checkpoint = Some(DecodedCheckpoint {
                        scope_ticket,
                        record_ordinal: record.ordinal,
                        checkpoint: decoded,
                    });
                }
                Err(error) => {
                    set_first_error(
                        &mut first_error,
                        NativeLiveRecoveryScanError::CheckpointPayload {
                            record_ordinal: record.ordinal,
                            error,
                        },
                    );
                }
            }
            continue;
        }

        let classification = classify_non_checkpoint_kind(record.kind);
        let error = if let Some(observed_ordinal) = checkpoint_ordinal {
            NativeLiveRecoveryScanError::CheckpointNotFinal {
                checkpoint_ordinal: observed_ordinal,
                following_ordinal: record.ordinal,
                following_kind: classification,
            }
        } else {
            match classification {
                NativeLiveTrailingRecordKind::KnownUnsupported(kind) => {
                    NativeLiveRecoveryScanError::UnsupportedRecord {
                        record_ordinal: record.ordinal,
                        kind,
                    }
                }
                NativeLiveTrailingRecordKind::Unknown(kind) => {
                    NativeLiveRecoveryScanError::UnknownRecordKind {
                        record_ordinal: record.ordinal,
                        kind,
                    }
                }
            }
        };
        set_first_error(&mut first_error, error);
    }

    if let Some(record_ordinal) = unfinished_intent {
        return Err(NativeLiveRecoveryScanError::UnfinishedIntent { record_ordinal });
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    let Some(checkpoint) = decoded_checkpoint else {
        return Err(NativeLiveRecoveryScanError::MissingCheckpoint);
    };

    Ok(NativeLiveRecoveryEvidence {
        header,
        anchor,
        scope_ticket: checkpoint.scope_ticket,
        checkpoint_record_ordinal: checkpoint.record_ordinal,
        recorded_checkpoint: checkpoint.checkpoint,
        requirement: recovery_requirement(checkpoint.checkpoint.phase),
    })
}

fn reject_unverified_predecessor(
    header: &AuditContainerHeader,
) -> Result<(), NativeLiveRecoveryScanError> {
    let Some(predecessor) = header.predecessor else {
        return Ok(());
    };
    Err(NativeLiveRecoveryScanError::PredecessorHistoryUnverified {
        current_generation: header.generation,
        predecessor_container_id: predecessor.container_id,
        predecessor_generation: predecessor.generation,
    })
}

fn set_first_error(
    slot: &mut Option<NativeLiveRecoveryScanError>,
    error: NativeLiveRecoveryScanError,
) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn classify_non_checkpoint_kind(kind: AuditRecordKind) -> NativeLiveTrailingRecordKind {
    if kind == AuditRecordKind::NORMALIZED_EVENT
        || kind == AuditRecordKind::SCHEDULER_COMMIT
        || kind == AuditRecordKind::NATIVE_INGRESS
        || kind == AuditRecordKind::NATIVE_DISPOSITION
        || kind == AuditRecordKind::ABORTED_RESERVATION
        || kind == AuditRecordKind::FAULT
    {
        NativeLiveTrailingRecordKind::KnownUnsupported(kind)
    } else {
        NativeLiveTrailingRecordKind::Unknown(kind.0)
    }
}

fn validate_checkpoint_against_header(
    header: &AuditContainerHeader,
    checkpoint: NativeLiveCheckpoint,
) -> Result<(), NativeLiveRecoveryCheckpointError> {
    if checkpoint.expected_identity != header.venue_identity {
        return Err(NativeLiveRecoveryCheckpointError::HeaderMismatch(
            NativeLiveCheckpointHeaderField::VenueIdentity,
        ));
    }
    if checkpoint.expected_instrument_binding != header.instrument_definition_binding {
        return Err(NativeLiveRecoveryCheckpointError::HeaderMismatch(
            NativeLiveCheckpointHeaderField::InstrumentDefinitionBinding,
        ));
    }
    if checkpoint.expected_market_data_source != header.market_data_source {
        return Err(NativeLiveRecoveryCheckpointError::HeaderMismatch(
            NativeLiveCheckpointHeaderField::MarketDataSource,
        ));
    }
    if checkpoint.expected_order_entry_source != header.order_entry_source {
        return Err(NativeLiveRecoveryCheckpointError::HeaderMismatch(
            NativeLiveCheckpointHeaderField::OrderEntrySource,
        ));
    }
    if checkpoint.expected_drop_copy_source != header.drop_copy_source {
        return Err(NativeLiveRecoveryCheckpointError::HeaderMismatch(
            NativeLiveCheckpointHeaderField::DropCopySource,
        ));
    }
    if checkpoint.monotonic_clock_epoch != header.monotonic_clock_epoch {
        return Err(NativeLiveRecoveryCheckpointError::HeaderMismatch(
            NativeLiveCheckpointHeaderField::MonotonicClockEpoch,
        ));
    }
    if checkpoint.expected_first_source_capture.0 == 0 {
        return Err(
            NativeLiveRecoveryCheckpointError::InvalidExpectedFirstSourceCapture(
                checkpoint.expected_first_source_capture,
            ),
        );
    }
    if let Some(actual) = checkpoint.last_source_capture
        && actual < checkpoint.expected_first_source_capture
    {
        return Err(
            NativeLiveRecoveryCheckpointError::InvalidLastSourceCapture {
                expected_at_least: checkpoint.expected_first_source_capture,
                actual,
            },
        );
    }
    if let Some(actual) = checkpoint.last_outbound_frame
        && actual == u64::MAX
    {
        return Err(NativeLiveRecoveryCheckpointError::InvalidLastOutboundFrame(
            actual,
        ));
    }
    if checkpoint.next_commit_ordinal == 0 {
        return Err(NativeLiveRecoveryCheckpointError::InvalidNextCommitOrdinal(
            checkpoint.next_commit_ordinal,
        ));
    }
    Ok(())
}

const fn recovery_requirement(phase: NativeLivePhase) -> NativeLiveRecoveryRequirement {
    match phase {
        NativeLivePhase::Ready => NativeLiveRecoveryRequirement::OwnedReplayRequired(
            NativeLiveRecordedRunnablePhase::Ready,
        ),
        NativeLivePhase::SafetyPending => NativeLiveRecoveryRequirement::OwnedReplayRequired(
            NativeLiveRecordedRunnablePhase::SafetyPending,
        ),
        NativeLivePhase::KilledRecovery => NativeLiveRecoveryRequirement::OwnedReplayRequired(
            NativeLiveRecordedRunnablePhase::KilledRecovery,
        ),
        NativeLivePhase::Ambiguous => NativeLiveRecoveryRequirement::ManualReconciliation(
            NativeLiveRecordedNonRunnablePhase::Ambiguous,
        ),
        NativeLivePhase::Failed => NativeLiveRecoveryRequirement::ManualReconciliation(
            NativeLiveRecordedNonRunnablePhase::Failed,
        ),
    }
}
