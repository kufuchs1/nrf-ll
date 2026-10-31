//! Legacy advertising and filter accept list commands.

use super::{
    ADV_INTERVAL_MAX,
    ADV_INTERVAL_MIN,
    STATUS_DISALLOWED,
    STATUS_INVALID_PARAMETERS,
    STATUS_LIMITED_RESOURCES,
    STATUS_MEMORY_FULL,
    STATUS_SUCCESS,
    STATUS_UNSUPPORTED,
};
use crate::{
    advertiser::legacy::{DATA_MAX, FILTER_LIST_SIZE, Kind, Settings},
    pdu::Peer,
};

/// Runs an advertising or filter accept list command on `settings`. Returns
/// the status, the length of the return parameters written to `returned` and
/// the new advertising enable state.
pub(super) fn command(
    settings: &mut Settings,
    (opcode, params, returned): (u16, &[u8], &mut [u8; 8]),
    enabled: bool,
    connected: bool,
) -> (u8, usize, Option<bool>) {
    let status = match opcode {
        0x2005 => match params.first_chunk::<6>() {
            _ if enabled => STATUS_DISALLOWED,
            Some(address) => {
                settings.address = Peer::new(*address, true);
                settings.own = settings.address;
                STATUS_SUCCESS
            },
            None => STATUS_INVALID_PARAMETERS,
        },
        0x2006 if enabled => STATUS_DISALLOWED,
        0x2006 => set_parameters(settings, params),
        0x2007 => {
            if let Some(power) = returned.first_mut() {
                *power = 0;
            }
            return (STATUS_SUCCESS, 1, None);
        },
        0x2008 | 0x2009 => set_data(settings, opcode == 0x2009, params),
        0x200A => {
            let enable = params.first().is_some_and(|&value| value != 0);
            let status = if !enable {
                STATUS_SUCCESS
            } else if !settings.address.random || settings.address.address == [0; 6] {
                STATUS_INVALID_PARAMETERS
            } else if connected && settings.kind.is_connectable() {
                STATUS_LIMITED_RESOURCES
            } else if connected {
                STATUS_DISALLOWED
            } else {
                STATUS_SUCCESS
            };
            return (status, 0, Some(enable));
        },
        0x200F => {
            if let Some(size) = returned.first_mut() {
                *size = u8::try_from(FILTER_LIST_SIZE).unwrap_or(u8::MAX);
            }
            return (STATUS_SUCCESS, 1, None);
        },
        _ if enabled && settings.filter_policy != 0 => STATUS_DISALLOWED,
        0x2010 => {
            settings.filter.clear();
            STATUS_SUCCESS
        },
        _ => filter_command(settings, opcode == 0x2011, params),
    };
    (status, 0, None)
}

/// Adds a device to or removes it from the filter accept list.
fn filter_command(settings: &mut Settings, add: bool, params: &[u8]) -> u8 {
    let Some((&address_type, rest)) = params.split_first() else { return STATUS_INVALID_PARAMETERS };
    if address_type == 0xFF {
        return STATUS_SUCCESS;
    }
    let Some(address) = rest.first_chunk::<6>().copied().filter(|_| address_type <= 1) else {
        return STATUS_INVALID_PARAMETERS;
    };
    let peer = Peer::new(address, address_type == 1);
    if !add {
        settings.filter.remove(peer);
        return STATUS_SUCCESS;
    }
    if settings.filter.add(peer) { STATUS_SUCCESS } else { STATUS_MEMORY_FULL }
}

/// Stores advertising or scan response data.
fn set_data(settings: &mut Settings, scan: bool, params: &[u8]) -> u8 {
    let Some((&len, data)) = params.split_first() else { return STATUS_INVALID_PARAMETERS };
    let len_usize = usize::from(len);
    let Some(source) = data.get(..len_usize).filter(|_| len_usize <= DATA_MAX) else {
        return STATUS_INVALID_PARAMETERS;
    };
    let (target, target_len) =
        if scan { (&mut settings.scan_data, &mut settings.scan_len) } else { (&mut settings.data, &mut settings.len) };
    if let Some(destination) = target.get_mut(..len_usize) {
        destination.copy_from_slice(source);
    }
    *target_len = len;
    STATUS_SUCCESS
}

/// Stores the advertising parameters after checking their ranges.
fn set_parameters(settings: &mut Settings, params: &[u8]) -> u8 {
    let Some(
        [
            min_low,
            min_high,
            max_low,
            max_high,
            kind_value,
            own_type,
            peer_type,
            peer0,
            peer1,
            peer2,
            peer3,
            peer4,
            peer5,
            channel_map,
            filter_policy,
        ],
    ) = params.first_chunk::<15>().copied()
    else {
        return STATUS_INVALID_PARAMETERS;
    };
    let Some(kind) = Kind::from_hci(kind_value) else { return STATUS_INVALID_PARAMETERS };
    let interval_min = u16::from_le_bytes([min_low, min_high]);
    let interval_max = u16::from_le_bytes([max_low, max_high]);
    let intervals_valid = kind == Kind::DirectedHighDuty
        || (interval_min <= interval_max && interval_min >= ADV_INTERVAL_MIN && interval_max <= ADV_INTERVAL_MAX);
    if !intervals_valid || own_type > 3 || peer_type > 1 || !(1..=0x07).contains(&channel_map) || filter_policy > 3 {
        return STATUS_INVALID_PARAMETERS;
    }
    if own_type & 0x01 == 0 {
        return STATUS_UNSUPPORTED;
    }
    settings.kind = kind;
    settings.private = own_type & 0x02 != 0;
    settings.interval = u32::from(interval_min).saturating_mul(625);
    settings.peer = Peer::new([peer0, peer1, peer2, peer3, peer4, peer5], peer_type == 1);
    settings.channel_map = channel_map;
    settings.filter_policy = filter_policy;
    STATUS_SUCCESS
}
