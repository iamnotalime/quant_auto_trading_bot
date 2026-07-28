use crate::types::{InstrumentId, PriceTicks, Quantity, Side, TimestampNs};
use crate::venue::{
    CancelAll, CancelOrder, CancelScope, ClientOrderId, NewOrder, OrderCommand, ReplaceOrder,
    TimeInForce, VenueOrderId,
};

pub(crate) const ORDER_COMMAND_WIRE_LEN: usize = 56;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OrderCommandCodecError {
    InvalidCommand,
    InvalidTag(u8),
    InvalidSide(u8),
    InvalidOption(u8),
    NonCanonical,
}

pub(crate) fn encode_order_command(
    command: OrderCommand,
    output: &mut [u8; ORDER_COMMAND_WIRE_LEN],
) -> Result<(), OrderCommandCodecError> {
    command
        .validate()
        .map_err(|_| OrderCommandCodecError::InvalidCommand)?;
    output.fill(0);
    match command {
        OrderCommand::New(order) => {
            output[0] = 1;
            output[1] = order.side as u8;
            output[2] = order.time_in_force as u8;
            write_u32(output, 4, order.instrument.0);
            write_u64(output, 8, order.client_order_id.0);
            write_i64(output, 32, order.price.0);
            write_i64(output, 40, order.quantity.0);
            write_u64(output, 48, order.created_at.0);
        }
        OrderCommand::Cancel(order) => {
            output[0] = 2;
            write_u64(output, 8, order.client_order_id.0);
            write_u64(output, 16, order.venue_order_id.0);
            write_u64(output, 48, order.created_at.0);
        }
        OrderCommand::Replace(order) => {
            output[0] = 3;
            write_u64(output, 8, order.current_client_order_id.0);
            write_u64(output, 16, order.replacement_client_order_id.0);
            write_u64(output, 24, order.venue_order_id.0);
            write_i64(output, 32, order.new_price.0);
            write_i64(output, 40, order.new_quantity.0);
            write_u64(output, 48, order.created_at.0);
        }
        OrderCommand::CancelAll(command) => {
            output[0] = 4;
            match command.scope {
                CancelScope::Session => output[2] = 1,
                CancelScope::Instrument(instrument) => {
                    output[2] = 2;
                    write_u32(output, 4, instrument.0);
                }
            }
            write_u64(output, 48, command.created_at.0);
        }
    }
    Ok(())
}

pub(crate) fn decode_order_command(
    input: &[u8; ORDER_COMMAND_WIRE_LEN],
) -> Result<OrderCommand, OrderCommandCodecError> {
    let command = match input[0] {
        1 => OrderCommand::New(NewOrder {
            client_order_id: ClientOrderId(read_u64(input, 8)),
            instrument: InstrumentId(read_u32(input, 4)),
            side: decode_side(input[1])?,
            price: PriceTicks(read_i64(input, 32)),
            quantity: Quantity(read_i64(input, 40)),
            time_in_force: decode_time_in_force(input[2])?,
            created_at: TimestampNs(read_u64(input, 48)),
        }),
        2 => OrderCommand::Cancel(CancelOrder {
            client_order_id: ClientOrderId(read_u64(input, 8)),
            venue_order_id: VenueOrderId(read_u64(input, 16)),
            created_at: TimestampNs(read_u64(input, 48)),
        }),
        3 => OrderCommand::Replace(ReplaceOrder {
            current_client_order_id: ClientOrderId(read_u64(input, 8)),
            replacement_client_order_id: ClientOrderId(read_u64(input, 16)),
            venue_order_id: VenueOrderId(read_u64(input, 24)),
            new_price: PriceTicks(read_i64(input, 32)),
            new_quantity: Quantity(read_i64(input, 40)),
            created_at: TimestampNs(read_u64(input, 48)),
        }),
        4 => OrderCommand::CancelAll(CancelAll {
            scope: match input[2] {
                1 => CancelScope::Session,
                2 => CancelScope::Instrument(InstrumentId(read_u32(input, 4))),
                option => return Err(OrderCommandCodecError::InvalidOption(option)),
            },
            created_at: TimestampNs(read_u64(input, 48)),
        }),
        tag => return Err(OrderCommandCodecError::InvalidTag(tag)),
    };
    command
        .validate()
        .map_err(|_| OrderCommandCodecError::InvalidCommand)?;
    let mut canonical = [0_u8; ORDER_COMMAND_WIRE_LEN];
    encode_order_command(command, &mut canonical)?;
    if canonical != *input {
        return Err(OrderCommandCodecError::NonCanonical);
    }
    Ok(command)
}

const fn decode_side(code: u8) -> Result<Side, OrderCommandCodecError> {
    match code {
        1 => Ok(Side::Buy),
        2 => Ok(Side::Sell),
        _ => Err(OrderCommandCodecError::InvalidSide(code)),
    }
}

const fn decode_time_in_force(code: u8) -> Result<TimeInForce, OrderCommandCodecError> {
    match code {
        1 => Ok(TimeInForce::Day),
        2 => Ok(TimeInForce::ImmediateOrCancel),
        3 => Ok(TimeInForce::FillOrKill),
        4 => Ok(TimeInForce::GoodTillCancel),
        5 => Ok(TimeInForce::PostOnly),
        _ => Err(OrderCommandCodecError::InvalidOption(code)),
    }
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(output: &mut [u8], offset: usize, value: i64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed field"))
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}

fn read_i64(input: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}
