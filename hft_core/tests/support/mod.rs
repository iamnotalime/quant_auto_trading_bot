#![allow(dead_code)]

use quant_hft_core::control::{
    AuthenticationError, ConfigDigest, ControlAuthenticator, ControlCommand, ControlDecision,
    ControlGate, ControlGateConfig, ControlIdentity, ControlProtocolVersion, VerifiedControl,
};
use quant_hft_core::kill::KillLatch;
use quant_hft_core::reference_data::{
    FixedInstrumentValue, InstrumentDefinition, NativeProductId, RationalScale,
    ReferenceDataAuthorityId, ReferenceDataDigest, SelfTradePreventionInstruction,
};
use quant_hft_core::types::{
    CurrencyId, InstrumentId, PriceTicks, Quantity, Sequence, TimestampNs, VenueId,
};

const IDENTITY: ControlIdentity = ControlIdentity {
    controller_id: 1,
    engine_id: 2,
    deployment_id: 3,
};

pub const fn instrument_definition(
    venue: VenueId,
    instrument: InstrumentId,
) -> InstrumentDefinition {
    InstrumentDefinition {
        venue,
        instrument,
        native_product: NativeProductId(1),
        authority: ReferenceDataAuthorityId(1),
        reference_data_version: 1,
        reference_data_digest: ReferenceDataDigest([0x5A; 32]),
        valid_from: TimestampNs(1),
        valid_until: TimestampNs(u64::MAX),
        price_scale: RationalScale {
            numerator: 1,
            denominator: 1,
        },
        quantity_scale: RationalScale {
            numerator: 1,
            denominator: 1,
        },
        fixed_value: FixedInstrumentValue {
            settlement_currency: CurrencyId(840),
            settlement_units_per_price_tick: 1,
            contract_multiplier: 1,
        },
        minimum_price: PriceTicks(1),
        maximum_price: PriceTicks(i64::MAX),
        price_increment: PriceTicks(1),
        minimum_quantity: Quantity(1),
        maximum_quantity: Quantity(i64::MAX),
        quantity_increment: Quantity(1),
        continuous_trading_status_code: 1,
        self_trade_prevention: SelfTradePreventionInstruction(1),
        cancel_on_disconnect_required: false,
    }
}

#[derive(Clone, Copy)]
struct FixedAuthenticator {
    verified: VerifiedControl,
}

impl ControlAuthenticator for FixedAuthenticator {
    type Checkpoint = ();

    fn checkpoint(&self) -> Self::Checkpoint {}

    fn restore(&mut self, (): Self::Checkpoint) {}

    fn verify_and_decode(
        &mut self,
        _frame: &[u8],
        _scratch: &mut [u8],
    ) -> Result<VerifiedControl, AuthenticationError> {
        Ok(self.verified)
    }
}

pub fn authenticated_arm(
    config_epoch: u64,
    config_digest: ConfigDigest,
    sequence: Sequence,
    accepted_at: TimestampNs,
    lease_deadline: TimestampNs,
) -> ControlDecision {
    authenticated_decision(
        ControlCommand::Arm,
        config_epoch,
        config_digest,
        sequence,
        accepted_at,
        lease_deadline
            .checked_duration_since(accepted_at)
            .expect("arm lease must follow acceptance"),
    )
}

pub fn authenticated_heartbeat(
    config_epoch: u64,
    config_digest: ConfigDigest,
    sequence: Sequence,
    accepted_at: TimestampNs,
    lease_deadline: TimestampNs,
) -> ControlDecision {
    authenticated_decision(
        ControlCommand::Heartbeat,
        config_epoch,
        config_digest,
        sequence,
        accepted_at,
        lease_deadline
            .checked_duration_since(accepted_at)
            .expect("heartbeat lease must follow acceptance"),
    )
}

pub fn authenticated_disarm(
    config_epoch: u64,
    config_digest: ConfigDigest,
    sequence: Sequence,
    accepted_at: TimestampNs,
) -> ControlDecision {
    authenticated_decision(
        ControlCommand::Disarm,
        config_epoch,
        config_digest,
        sequence,
        accepted_at,
        2,
    )
}

pub fn authenticated_kill(
    config_epoch: u64,
    config_digest: ConfigDigest,
    sequence: Sequence,
    accepted_at: TimestampNs,
) -> ControlDecision {
    authenticated_decision(
        ControlCommand::Kill,
        config_epoch,
        config_digest,
        sequence,
        accepted_at,
        2,
    )
}

fn authenticated_decision(
    command: ControlCommand,
    config_epoch: u64,
    config_digest: ConfigDigest,
    sequence: Sequence,
    accepted_at: TimestampNs,
    heartbeat_timeout_ns: u64,
) -> ControlDecision {
    assert!(sequence.0 > 0);
    assert!(accepted_at.0 > 1);
    assert!(heartbeat_timeout_ns > 0);
    let requires_armed = matches!(command, ControlCommand::Disarm | ControlCommand::Heartbeat);
    let first_sequence = if requires_armed {
        Sequence(sequence.0 - 1)
    } else {
        sequence
    };
    assert!(first_sequence.0 > 0);
    let mut gate = ControlGate::<1, 1>::new(ControlGateConfig {
        protocol_version: ControlProtocolVersion(1),
        identity: IDENTITY,
        config_digest,
        minimum_config_epoch: config_epoch,
        first_command_sequence: first_sequence,
        max_future_skew_ns: 1,
        max_command_lifetime_ns: 2,
        heartbeat_timeout_ns,
    })
    .expect("test control gate");
    let kill = KillLatch::new();
    let mut scratch = [0_u8; 1];

    if requires_armed {
        let prelude_at = TimestampNs(accepted_at.0 - 1);
        let mut authenticator = FixedAuthenticator {
            verified: verified(
                ControlCommand::Arm,
                config_epoch,
                config_digest,
                first_sequence,
                prelude_at,
            ),
        };
        gate.verify_and_apply(&mut authenticator, &[1], &mut scratch, prelude_at, &kill)
            .expect("authenticated arm prelude");
    }

    let mut authenticator = FixedAuthenticator {
        verified: verified(command, config_epoch, config_digest, sequence, accepted_at),
    };
    gate.verify_and_apply(&mut authenticator, &[1], &mut scratch, accepted_at, &kill)
        .expect("authenticated control decision")
}

fn verified(
    command: ControlCommand,
    config_epoch: u64,
    config_digest: ConfigDigest,
    sequence: Sequence,
    issued_at: TimestampNs,
) -> VerifiedControl {
    VerifiedControl {
        protocol_version: ControlProtocolVersion(1),
        identity: IDENTITY,
        config_digest,
        config_epoch,
        command_sequence: sequence,
        issued_at,
        expires_at: TimestampNs(issued_at.0 + 1),
        command,
    }
}
