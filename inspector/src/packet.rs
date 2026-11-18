use crate::reassembly::{Connection, Segment};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    Malformed,
    Fragmented,
    Unsupported,
}

pub fn parse_ethernet(bytes: &[u8]) -> Result<(Connection, Segment<'_>), PacketError> {
    let packet = SlicedPacket::from_ethernet(bytes).map_err(|_| PacketError::Malformed)?;
    let (source, destination) = match packet.net {
        Some(NetSlice::Ipv4(ip)) => {
            if ip.payload().fragmented {
                return Err(PacketError::Fragmented);
            }
            (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            )
        }
        Some(NetSlice::Ipv6(ip)) => {
            if ip.payload().fragmented {
                return Err(PacketError::Fragmented);
            }
            (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            )
        }
        _ => return Err(PacketError::Unsupported),
    };
    let Some(TransportSlice::Tcp(tcp)) = packet.transport else {
        return Err(PacketError::Unsupported);
    };
    // A SYN+ACK is the server half, not the beginning of a ClientHello stream.
    if tcp.syn() && tcp.ack() {
        return Err(PacketError::Unsupported);
    }
    Ok((
        Connection {
            source,
            destination,
            source_port: tcp.source_port(),
            destination_port: tcp.destination_port(),
        },
        Segment {
            sequence: tcp.sequence_number(),
            syn: tcp.syn(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            payload: tcp.payload(),
        },
    ))
}
