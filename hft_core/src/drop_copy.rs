//! Fixed-capacity reconciliation of private order-entry and independent drop-copy reports.
//!
//! The gate never treats one channel as authoritative by itself. Reports may arrive
//! on either channel first, but trading remains ineligible until every report has an
//! exact peer. A duplicate or a report with the same venue identity but different
//! economics is a definite reconciliation fault.

use crate::types::{Sequence, TimestampNs};
use crate::venue::{ClientOrderId, OrderEvent, SessionEvent, TradeId};

/// Static cursor for one independently sequenced drop-copy session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropCopyConfig {
    pub first_sequence: Sequence,
    /// Maximum disciplined UTC interval for the oldest unresolved cross-channel
    /// report. Zero is invalid because it would make the boundary scheduler-dependent.
    pub pending_timeout_ns: u64,
}

/// Channel on which a pending or duplicate report was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropCopyChannel {
    OrderEntry,
    DropCopy,
}

/// Compact event variant retained in reconciliation errors.
///
/// The complete authenticated facts remain in the source journal and in the
/// fixed-capacity gate. Errors carry only the identity needed to locate those
/// facts, avoiding copies of two full [`OrderEvent`] values through every engine
/// error path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DropCopyReportKind {
    Accepted = 1,
    Rejected = 2,
    Canceled = 3,
    Fill = 4,
    LifecycleCorrection = 5,
}

/// Allocation-free identity for a drop-copy reconciliation diagnostic.
///
/// `primary_id` is the client-order ID for ordinary reports and the correction
/// ID for lifecycle corrections. `secondary_id` is the trade ID for fills, the
/// target trade ID for corrections, and zero for other variants.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DropCopyReportIdentity {
    pub kind: DropCopyReportKind,
    pub primary_id: u64,
    pub secondary_id: u64,
}

impl DropCopyReportIdentity {
    #[must_use]
    pub const fn from_report(report: OrderEvent) -> Self {
        match report {
            OrderEvent::Accepted(value) => Self {
                kind: DropCopyReportKind::Accepted,
                primary_id: value.client_order_id.0,
                secondary_id: 0,
            },
            OrderEvent::Rejected(value) => Self {
                kind: DropCopyReportKind::Rejected,
                primary_id: value.client_order_id.0,
                secondary_id: 0,
            },
            OrderEvent::Canceled(value) => Self {
                kind: DropCopyReportKind::Canceled,
                primary_id: value.client_order_id.0,
                secondary_id: 0,
            },
            OrderEvent::Fill(value) => Self {
                kind: DropCopyReportKind::Fill,
                primary_id: value.client_order_id.0,
                secondary_id: value.trade_id.0,
            },
            OrderEvent::LifecycleCorrectionObserved(value) => Self {
                kind: DropCopyReportKind::LifecycleCorrection,
                primary_id: value.correction_id.0,
                secondary_id: value.target_trade_id.0,
            },
        }
    }
}

/// Fixed reconciliation failure. The engine converts every instance into a
/// fail-closed kill before another order can be originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropCopyError {
    InvalidConfiguration,
    SessionNotLive,
    SessionUnavailable(SessionEvent),
    SequenceMismatch {
        expected: Sequence,
        received: Sequence,
    },
    SequenceExhausted,
    DuplicateReport {
        channel: DropCopyChannel,
        report: DropCopyReportIdentity,
    },
    ReportMismatch {
        order_entry: DropCopyReportIdentity,
        drop_copy: DropCopyReportIdentity,
    },
    Capacity {
        channel: DropCopyChannel,
        capacity: usize,
    },
    PendingDeadlineOverflow {
        observed: TimestampNs,
        timeout_ns: u64,
    },
    PendingExpired {
        deadline: TimestampNs,
        observed: TimestampNs,
    },
}

/// Observable bounded reconciliation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropCopyStatus {
    pub session_live: bool,
    pub expected_sequence: Sequence,
    pub pending_order_entry: usize,
    pub pending_drop_copy: usize,
    pub pending_deadline: Option<TimestampNs>,
}

impl DropCopyStatus {
    #[must_use]
    pub const fn synchronized(self) -> bool {
        self.session_live && self.pending_order_entry == 0 && self.pending_drop_copy == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DropCopyGate<const CAPACITY: usize> {
    expected_sequence: Sequence,
    pending_timeout_ns: u64,
    session_live: bool,
    order_entry: [Option<PendingReport>; CAPACITY],
    drop_copy: [Option<PendingReport>; CAPACITY],
    matched: [Option<OrderEvent>; CAPACITY],
    order_entry_len: usize,
    drop_copy_len: usize,
    matched_len: usize,
    matched_next: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingReport {
    report: OrderEvent,
    deadline: TimestampNs,
}

impl<const CAPACITY: usize> DropCopyGate<CAPACITY> {
    pub(crate) const fn new(config: DropCopyConfig) -> Result<Self, DropCopyError> {
        if config.first_sequence.0 == 0 || config.pending_timeout_ns == 0 || CAPACITY == 0 {
            return Err(DropCopyError::InvalidConfiguration);
        }
        Ok(Self {
            expected_sequence: config.first_sequence,
            pending_timeout_ns: config.pending_timeout_ns,
            session_live: false,
            order_entry: [None; CAPACITY],
            drop_copy: [None; CAPACITY],
            matched: [None; CAPACITY],
            order_entry_len: 0,
            drop_copy_len: 0,
            matched_len: 0,
            matched_next: 0,
        })
    }

    pub(crate) const fn status(&self) -> DropCopyStatus {
        DropCopyStatus {
            session_live: self.session_live,
            expected_sequence: self.expected_sequence,
            pending_order_entry: self.order_entry_len,
            pending_drop_copy: self.drop_copy_len,
            pending_deadline: self.oldest_pending_deadline(),
        }
    }

    pub(crate) const fn synchronized(&self) -> bool {
        self.status().synchronized()
    }

    pub(crate) fn observe_order_entry(
        &mut self,
        report: OrderEvent,
        observed: TimestampNs,
    ) -> Result<(), DropCopyError> {
        self.check_pending_liveness(observed)?;
        reconcile(
            report,
            DropCopyChannel::OrderEntry,
            &mut self.order_entry,
            &mut self.order_entry_len,
            &mut self.drop_copy,
            &mut self.drop_copy_len,
            &mut self.matched,
            &mut self.matched_len,
            &mut self.matched_next,
            observed,
            self.pending_timeout_ns,
        )
    }

    pub(crate) fn observe_drop_copy(
        &mut self,
        sequence: Sequence,
        report: OrderEvent,
        observed: TimestampNs,
    ) -> Result<(), DropCopyError> {
        self.check_pending_liveness(observed)?;
        let next_sequence = self.validated_next_sequence(sequence)?;
        if !self.session_live {
            self.expected_sequence = next_sequence;
            return Err(DropCopyError::SessionNotLive);
        }
        reconcile(
            report,
            DropCopyChannel::DropCopy,
            &mut self.drop_copy,
            &mut self.drop_copy_len,
            &mut self.order_entry,
            &mut self.order_entry_len,
            &mut self.matched,
            &mut self.matched_len,
            &mut self.matched_next,
            observed,
            self.pending_timeout_ns,
        )?;
        self.expected_sequence = next_sequence;
        Ok(())
    }

    pub(crate) fn observe_session(
        &mut self,
        sequence: Sequence,
        event: SessionEvent,
        observed: TimestampNs,
    ) -> Result<(), DropCopyError> {
        self.check_pending_liveness(observed)?;
        let next_sequence = self.validated_next_sequence(sequence)?;
        self.expected_sequence = next_sequence;
        match event {
            SessionEvent::LogonAccepted => {
                self.session_live = true;
                Ok(())
            }
            SessionEvent::Heartbeat => Ok(()),
            SessionEvent::LogonRejected { .. }
            | SessionEvent::ReplayComplete { .. }
            | SessionEvent::SnapshotRequired
            | SessionEvent::Logout { .. } => {
                self.session_live = false;
                Err(DropCopyError::SessionUnavailable(event))
            }
        }
    }

    fn validated_next_sequence(&mut self, received: Sequence) -> Result<Sequence, DropCopyError> {
        if received != self.expected_sequence {
            self.session_live = false;
            return Err(DropCopyError::SequenceMismatch {
                expected: self.expected_sequence,
                received,
            });
        }
        Ok(Sequence(
            received
                .0
                .checked_add(1)
                .ok_or(DropCopyError::SequenceExhausted)?,
        ))
    }

    pub(crate) const fn check_pending_liveness(
        &self,
        observed: TimestampNs,
    ) -> Result<(), DropCopyError> {
        match self.oldest_pending_deadline() {
            Some(deadline) if observed.0 > deadline.0 => {
                Err(DropCopyError::PendingExpired { deadline, observed })
            }
            _ => Ok(()),
        }
    }

    const fn oldest_pending_deadline(&self) -> Option<TimestampNs> {
        let mut oldest: Option<TimestampNs> = None;
        let mut index = 0;
        while index < self.order_entry_len {
            if let Some(pending) = self.order_entry[index] {
                let earlier = match oldest {
                    Some(deadline) => pending.deadline.0 < deadline.0,
                    None => true,
                };
                if earlier {
                    oldest = Some(pending.deadline);
                }
            }
            index += 1;
        }
        index = 0;
        while index < self.drop_copy_len {
            if let Some(pending) = self.drop_copy[index] {
                let earlier = match oldest {
                    Some(deadline) => pending.deadline.0 < deadline.0,
                    None => true,
                };
                if earlier {
                    oldest = Some(pending.deadline);
                }
            }
            index += 1;
        }
        oldest
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixed two-channel and recent-history owners remain explicit and allocation-free"
)]
fn reconcile<const CAPACITY: usize>(
    incoming: OrderEvent,
    incoming_channel: DropCopyChannel,
    same: &mut [Option<PendingReport>; CAPACITY],
    same_len: &mut usize,
    opposite: &mut [Option<PendingReport>; CAPACITY],
    opposite_len: &mut usize,
    matched: &mut [Option<OrderEvent>; CAPACITY],
    matched_len: &mut usize,
    matched_next: &mut usize,
    observed: TimestampNs,
    pending_timeout_ns: u64,
) -> Result<(), DropCopyError> {
    for existing in matched.iter().take(*matched_len).copied().flatten() {
        if existing == incoming || same_report_identity(existing, incoming) {
            return Err(DropCopyError::DuplicateReport {
                channel: incoming_channel,
                report: DropCopyReportIdentity::from_report(incoming),
            });
        }
    }
    for existing in same.iter().take(*same_len).copied().flatten() {
        let existing = existing.report;
        if existing == incoming || same_report_identity(existing, incoming) {
            return Err(DropCopyError::DuplicateReport {
                channel: incoming_channel,
                report: DropCopyReportIdentity::from_report(incoming),
            });
        }
    }

    for index in 0..*opposite_len {
        let existing = opposite[index]
            .expect("occupied reconciliation prefix")
            .report;
        if existing == incoming {
            remove_at(opposite, opposite_len, index);
            remember_matched(matched, matched_len, matched_next, incoming);
            return Ok(());
        }
        // Each authenticated channel is ordered. Other clients may interleave
        // differently, but the earliest still-unmatched report for this client must
        // be identical. A later exact report cannot bless an earlier divergence.
        if same_reconciliation_lane(existing, incoming) {
            let (order_entry, drop_copy) = match incoming_channel {
                DropCopyChannel::OrderEntry => (incoming, existing),
                DropCopyChannel::DropCopy => (existing, incoming),
            };
            return Err(DropCopyError::ReportMismatch {
                order_entry: DropCopyReportIdentity::from_report(order_entry),
                drop_copy: DropCopyReportIdentity::from_report(drop_copy),
            });
        }
    }

    if *same_len == CAPACITY {
        return Err(DropCopyError::Capacity {
            channel: incoming_channel,
            capacity: CAPACITY,
        });
    }
    let deadline =
        observed
            .checked_add(pending_timeout_ns)
            .ok_or(DropCopyError::PendingDeadlineOverflow {
                observed,
                timeout_ns: pending_timeout_ns,
            })?;
    same[*same_len] = Some(PendingReport {
        report: incoming,
        deadline,
    });
    *same_len += 1;
    Ok(())
}

fn remember_matched<const CAPACITY: usize>(
    matched: &mut [Option<OrderEvent>; CAPACITY],
    len: &mut usize,
    next: &mut usize,
    report: OrderEvent,
) {
    matched[*next] = Some(report);
    *next = (*next + 1) % CAPACITY;
    *len = (*len + 1).min(CAPACITY);
}

fn remove_at<const CAPACITY: usize>(
    reports: &mut [Option<PendingReport>; CAPACITY],
    len: &mut usize,
    index: usize,
) {
    for cursor in index..len.saturating_sub(1) {
        reports[cursor] = reports[cursor + 1];
    }
    *len -= 1;
    reports[*len] = None;
}

const fn report_client_order_id(report: OrderEvent) -> Option<ClientOrderId> {
    match report {
        OrderEvent::Accepted(value) => Some(value.client_order_id),
        OrderEvent::Rejected(value) => Some(value.client_order_id),
        OrderEvent::Canceled(value) => Some(value.client_order_id),
        OrderEvent::Fill(value) => Some(value.client_order_id),
        OrderEvent::LifecycleCorrectionObserved(_) => None,
    }
}

const fn same_reconciliation_lane(left: OrderEvent, right: OrderEvent) -> bool {
    match (left, right) {
        (
            OrderEvent::LifecycleCorrectionObserved(left),
            OrderEvent::LifecycleCorrectionObserved(right),
        ) => left.correction_id.0 == right.correction_id.0,
        (OrderEvent::LifecycleCorrectionObserved(_), _)
        | (_, OrderEvent::LifecycleCorrectionObserved(_)) => false,
        _ => match (report_client_order_id(left), report_client_order_id(right)) {
            (Some(left), Some(right)) => left.0 == right.0,
            _ => false,
        },
    }
}

fn same_report_identity(left: OrderEvent, right: OrderEvent) -> bool {
    match (left, right) {
        (OrderEvent::Accepted(left), OrderEvent::Accepted(right)) => {
            left.client_order_id == right.client_order_id
        }
        (OrderEvent::Rejected(left), OrderEvent::Rejected(right)) => {
            left.client_order_id == right.client_order_id
        }
        (OrderEvent::Canceled(left), OrderEvent::Canceled(right)) => {
            left.client_order_id == right.client_order_id
        }
        (OrderEvent::Fill(left), OrderEvent::Fill(right)) => {
            fill_identity(left.client_order_id, left.trade_id)
                == fill_identity(right.client_order_id, right.trade_id)
        }
        (
            OrderEvent::LifecycleCorrectionObserved(left),
            OrderEvent::LifecycleCorrectionObserved(right),
        ) => left.correction_id == right.correction_id,
        _ => false,
    }
}

const fn fill_identity(client_order_id: ClientOrderId, trade_id: TradeId) -> (u64, u64) {
    (client_order_id.0, trade_id.0)
}

#[cfg(test)]
mod tests {
    use super::{
        DropCopyChannel, DropCopyConfig, DropCopyError, DropCopyGate, DropCopyReportIdentity,
    };
    use crate::types::{PriceTicks, Quantity, Sequence, TimestampNs};
    use crate::venue::{
        Accepted, Canceled, ClientOrderId, Fill, LifecycleCorrectionDigest, LifecycleCorrectionId,
        LifecycleCorrectionKind, LifecycleCorrectionObserved, LiquidityFlag, OrderEvent,
        RejectCode, Rejected, SessionEvent, TradeId, VenueOrderId,
    };

    const REPORT: OrderEvent = OrderEvent::Accepted(Accepted {
        client_order_id: ClientOrderId(7),
        venue_order_id: VenueOrderId(17),
        price: PriceTicks(101),
        quantity: Quantity(3),
    });
    const NOW: TimestampNs = TimestampNs(100);
    const CORRECTION: OrderEvent =
        OrderEvent::LifecycleCorrectionObserved(LifecycleCorrectionObserved {
            correction_id: LifecycleCorrectionId(81),
            target_trade_id: TradeId(71),
            kind: LifecycleCorrectionKind::Bust,
            canonical_payload_digest: LifecycleCorrectionDigest([0xA1; 32]),
        });

    const fn config() -> DropCopyConfig {
        DropCopyConfig {
            first_sequence: Sequence(1),
            pending_timeout_ns: 10,
        }
    }

    #[test]
    fn either_arrival_order_reconciles_exactly() {
        let mut first = DropCopyGate::<2>::new(config()).unwrap();
        first
            .observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        first.observe_order_entry(REPORT, NOW).unwrap();
        assert!(!first.synchronized());
        first.observe_drop_copy(Sequence(2), REPORT, NOW).unwrap();
        assert!(first.synchronized());
        assert_eq!(
            first.observe_drop_copy(Sequence(3), REPORT, NOW),
            Err(DropCopyError::DuplicateReport {
                channel: DropCopyChannel::DropCopy,
                report: DropCopyReportIdentity::from_report(REPORT),
            })
        );

        let mut second = DropCopyGate::<2>::new(config()).unwrap();
        second
            .observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        second.observe_drop_copy(Sequence(2), REPORT, NOW).unwrap();
        second.observe_order_entry(REPORT, NOW).unwrap();
        assert!(second.synchronized());
    }

    #[test]
    fn lifecycle_correction_pairs_only_by_exact_canonical_fact() {
        let mut gate = DropCopyGate::<2>::new(config()).unwrap();
        gate.observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        gate.observe_order_entry(CORRECTION, NOW).unwrap();

        let mismatched = OrderEvent::LifecycleCorrectionObserved(LifecycleCorrectionObserved {
            canonical_payload_digest: LifecycleCorrectionDigest([0xB2; 32]),
            ..match CORRECTION {
                OrderEvent::LifecycleCorrectionObserved(value) => value,
                _ => unreachable!(),
            }
        });
        assert_eq!(
            gate.observe_drop_copy(Sequence(2), mismatched, NOW),
            Err(DropCopyError::ReportMismatch {
                order_entry: DropCopyReportIdentity::from_report(CORRECTION),
                drop_copy: DropCopyReportIdentity::from_report(mismatched),
            })
        );

        let mut exact = DropCopyGate::<2>::new(config()).unwrap();
        exact
            .observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        exact
            .observe_drop_copy(Sequence(2), CORRECTION, NOW)
            .unwrap();
        exact.observe_order_entry(CORRECTION, NOW).unwrap();
        assert!(exact.synchronized());
        assert_eq!(
            exact.observe_order_entry(CORRECTION, NOW),
            Err(DropCopyError::DuplicateReport {
                channel: DropCopyChannel::OrderEntry,
                report: DropCopyReportIdentity::from_report(CORRECTION),
            })
        );
    }

    #[test]
    fn duplicate_and_economic_mismatch_are_definite_faults() {
        let mut gate = DropCopyGate::<2>::new(config()).unwrap();
        gate.observe_order_entry(REPORT, NOW).unwrap();
        assert_eq!(
            gate.observe_order_entry(REPORT, NOW),
            Err(DropCopyError::DuplicateReport {
                channel: DropCopyChannel::OrderEntry,
                report: DropCopyReportIdentity::from_report(REPORT),
            })
        );
        gate.observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();

        let different = OrderEvent::Accepted(Accepted {
            price: PriceTicks(102),
            ..match REPORT {
                OrderEvent::Accepted(value) => value,
                _ => unreachable!(),
            }
        });
        assert_eq!(
            gate.observe_drop_copy(Sequence(2), different, NOW),
            Err(DropCopyError::ReportMismatch {
                order_entry: DropCopyReportIdentity::from_report(REPORT),
                drop_copy: DropCopyReportIdentity::from_report(different),
            })
        );
    }

    #[test]
    fn unmatched_capacity_is_a_typed_fail_closed_boundary() {
        let mut gate = DropCopyGate::<1>::new(config()).unwrap();
        gate.observe_order_entry(REPORT, NOW).unwrap();
        let second = OrderEvent::Accepted(Accepted {
            client_order_id: ClientOrderId(8),
            venue_order_id: VenueOrderId(18),
            price: PriceTicks(103),
            quantity: Quantity(4),
        });
        assert_eq!(
            gate.observe_order_entry(second, NOW),
            Err(DropCopyError::Capacity {
                channel: DropCopyChannel::OrderEntry,
                capacity: 1,
            })
        );
    }

    #[test]
    fn earliest_unmatched_report_for_each_client_must_be_identical() {
        let rejected = OrderEvent::Rejected(Rejected {
            client_order_id: ClientOrderId(7),
            code: RejectCode(41),
        });
        let canceled = OrderEvent::Canceled(Canceled {
            client_order_id: ClientOrderId(7),
            venue_order_id: VenueOrderId(17),
            canceled_quantity: Quantity(3),
            leaves_quantity: Quantity::ZERO,
        });
        let fill_one = fill(71);
        let fill_two = fill(72);

        for (order_entry, drop_copy) in [
            (REPORT, rejected),
            (canceled, fill_one),
            (fill_one, fill_two),
        ] {
            let mut gate = DropCopyGate::<4>::new(config()).unwrap();
            gate.observe_order_entry(order_entry, NOW).unwrap();
            gate.observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
                .unwrap();
            assert_eq!(
                gate.observe_drop_copy(Sequence(2), drop_copy, NOW),
                Err(DropCopyError::ReportMismatch {
                    order_entry: DropCopyReportIdentity::from_report(order_entry),
                    drop_copy: DropCopyReportIdentity::from_report(drop_copy),
                })
            );
        }
    }

    #[test]
    fn one_channel_may_lead_without_relaxing_per_client_order() {
        let mut gate = DropCopyGate::<4>::new(config()).unwrap();
        gate.observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        let fill = fill(71);
        gate.observe_order_entry(REPORT, NOW).unwrap();
        gate.observe_order_entry(fill, NOW).unwrap();
        gate.observe_drop_copy(Sequence(2), REPORT, NOW).unwrap();
        assert!(!gate.synchronized());
        gate.observe_drop_copy(Sequence(3), fill, NOW).unwrap();
        assert!(gate.synchronized());

        let other = OrderEvent::Accepted(Accepted {
            client_order_id: ClientOrderId(8),
            venue_order_id: VenueOrderId(18),
            price: PriceTicks(102),
            quantity: Quantity(4),
        });

        let mut interleaved = DropCopyGate::<4>::new(config()).unwrap();
        interleaved
            .observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        interleaved.observe_order_entry(REPORT, NOW).unwrap();
        interleaved.observe_order_entry(other, NOW).unwrap();
        interleaved
            .observe_drop_copy(Sequence(2), other, NOW)
            .unwrap();
        interleaved
            .observe_drop_copy(Sequence(3), REPORT, NOW)
            .unwrap();
        assert!(interleaved.synchronized());
    }

    #[test]
    fn current_oldest_deadline_advances_after_pairing_and_exact_boundary_survives() {
        let mut gate = DropCopyGate::<4>::new(config()).unwrap();
        gate.observe_session(Sequence(1), SessionEvent::LogonAccepted, TimestampNs(99))
            .unwrap();
        gate.observe_order_entry(REPORT, TimestampNs(100)).unwrap();
        assert_eq!(gate.status().pending_deadline, Some(TimestampNs(110)));

        let other = OrderEvent::Accepted(Accepted {
            client_order_id: ClientOrderId(8),
            venue_order_id: VenueOrderId(18),
            price: PriceTicks(102),
            quantity: Quantity(4),
        });
        gate.observe_order_entry(other, TimestampNs(105)).unwrap();
        assert_eq!(gate.status().pending_deadline, Some(TimestampNs(110)));
        gate.observe_drop_copy(Sequence(2), REPORT, TimestampNs(110))
            .unwrap();
        assert_eq!(gate.status().pending_deadline, Some(TimestampNs(115)));
        assert_eq!(gate.check_pending_liveness(TimestampNs(115)), Ok(()));
        gate.observe_drop_copy(Sequence(3), other, TimestampNs(115))
            .unwrap();
        assert!(gate.synchronized());
        assert_eq!(gate.status().pending_deadline, None);

        let mut late = DropCopyGate::<4>::new(config()).unwrap();
        late.observe_session(Sequence(1), SessionEvent::LogonAccepted, TimestampNs(99))
            .unwrap();
        late.observe_order_entry(REPORT, TimestampNs(100)).unwrap();
        late.observe_order_entry(other, TimestampNs(105)).unwrap();
        late.observe_drop_copy(Sequence(2), REPORT, TimestampNs(110))
            .unwrap();
        assert_eq!(
            late.observe_drop_copy(Sequence(3), other, TimestampNs(116)),
            Err(DropCopyError::PendingExpired {
                deadline: TimestampNs(115),
                observed: TimestampNs(116),
            })
        );
        assert_eq!(late.status().expected_sequence, Sequence(3));
    }

    #[test]
    fn timeout_configuration_and_deadline_overflow_are_typed_boundaries() {
        assert_eq!(
            DropCopyGate::<2>::new(DropCopyConfig {
                first_sequence: Sequence(1),
                pending_timeout_ns: 0,
            }),
            Err(DropCopyError::InvalidConfiguration)
        );

        let mut gate = DropCopyGate::<2>::new(config()).unwrap();
        gate.observe_session(Sequence(1), SessionEvent::LogonAccepted, NOW)
            .unwrap();
        let observed = TimestampNs(u64::MAX - 5);
        assert_eq!(
            gate.observe_drop_copy(Sequence(2), REPORT, observed),
            Err(DropCopyError::PendingDeadlineOverflow {
                observed,
                timeout_ns: 10,
            })
        );
        assert_eq!(gate.status().expected_sequence, Sequence(2));
        assert_eq!(gate.status().pending_drop_copy, 0);
        assert_eq!(gate.status().pending_deadline, None);
    }

    #[test]
    fn replay_complete_cannot_invent_a_live_session_without_recovery_state() {
        let mut gate = DropCopyGate::<2>::new(config()).unwrap();
        let replay = SessionEvent::ReplayComplete {
            through: Sequence(99),
        };
        assert_eq!(
            gate.observe_session(Sequence(1), replay, NOW),
            Err(DropCopyError::SessionUnavailable(replay))
        );
        assert!(!gate.status().session_live);
        assert!(!gate.synchronized());
    }

    const fn fill(trade_id: u64) -> OrderEvent {
        OrderEvent::Fill(Fill {
            client_order_id: ClientOrderId(7),
            venue_order_id: VenueOrderId(17),
            trade_id: TradeId(trade_id),
            price: PriceTicks(101),
            quantity: Quantity(1),
            leaves_quantity: Quantity(2),
            liquidity: LiquidityFlag::Removed,
        })
    }
}
