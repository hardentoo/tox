/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! Codec implementation for encoding/decoding TCP Packets in terms of tokio-io
*/

use toxcore::tcp::packet::*;

use nom::{IResult, Offset};
use std::io::{Error, ErrorKind};
use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

/// implements tokio-io's Decoder and Encoder to deal with Packet
pub struct Codec;

impl Decoder for Codec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (consumed, packet) = match Packet::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other, format!("decode error: {:?}", e)))
            },
            IResult::Done(i, packet) => {
                (buf.offset(i), packet)
            }
        };

        // TODO memzero buf[..consumed] ?
        buf.split_to(consumed);

        Ok(Some(packet))
    }
}

impl Encoder for Codec {
    type Item = Packet;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut stack_buf = [0; 2050];
        match packet.to_bytes((&mut stack_buf, 0)).map(|tup| tup.1) {
            Ok(produced) => {
                buf.extend_from_slice(&stack_buf[..produced]);
                // TODO memzero stack_buf ?
                trace!("serialized packet: {} bytes", produced);
                Ok(())
            },
            Err(e) => {
                Err(Error::new(ErrorKind::Other, format!("encode error: {:?}", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ::toxcore::crypto_core::*;
    use ::toxcore::tcp::codec::*;

    fn check_packet(buf: &mut BytesMut, codec: &mut Codec, packet: Packet) {
        codec.encode(packet.clone(), buf).expect("Should encode");
        let res = codec.decode(buf).unwrap().expect("Should decode");
        assert_eq!(packet, res);
    }

    #[test]
    fn encode_decode() {
        let (pk, _) = gen_keypair();
        let mut buf = BytesMut::new();
        let mut codec = Codec {};

        check_packet(&mut buf, &mut codec, Packet::RouteRequest( RouteRequest { peer_pk: pk } ) );
        check_packet(&mut buf, &mut codec, Packet::RouteResponse( RouteResponse { connection_id: 42, pk: pk } ) );
        check_packet(&mut buf, &mut codec, Packet::ConnectNotification( ConnectNotification { connection_id: 42 } ) );
        check_packet(&mut buf, &mut codec, Packet::DisconnectNotification( DisconnectNotification { connection_id: 42 } ) );
        check_packet(&mut buf, &mut codec, Packet::PingRequest( PingRequest { ping_id: 4242 } ) );
        check_packet(&mut buf, &mut codec, Packet::PongResponse( PongResponse { ping_id: 4242 } ) );
        check_packet(&mut buf, &mut codec, Packet::OobSend( OobSend { destination_pk: pk, data: vec![13; 42] } ) );
        check_packet(&mut buf, &mut codec, Packet::OobReceive( OobReceive { sender_pk: pk, data: vec![13; 24] } ) );
        check_packet(&mut buf, &mut codec, Packet::Data( Data { connection_id: 42, data: vec![13; 2] } ) );
    }
}
