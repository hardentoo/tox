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
use toxcore::tcp::secure::*;

use nom::{IResult, Offset};
use std::io::{Error, ErrorKind};
use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

/// implements tokio-io's Decoder and Encoder to deal with Packet
pub struct Codec<'secure_channel> {
    channel: &'secure_channel Channel
}

impl<'secure_channel> Decoder for Codec<'secure_channel> {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedPacket
        let (consumed, encrypted_packet) = match EncryptedPacket::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                    format!("EncryptedPacket deserialize error: {:?}", e)))
            },
            IResult::Done(i, encrypted_packet) => {
                (buf.offset(i), encrypted_packet)
            }
        };

        // decrypt payload
        let decrypted_data = try!(self.channel.decrypt(&encrypted_packet.payload)
            .map_err(|_| Error::new(ErrorKind::Other, "EncryptedPacket decrypt failed"))
        );

        // deserialize Packet
        let mut local_stack = BytesMut::from(decrypted_data);
        match Packet::from_bytes(&mut local_stack) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other, "Packet should not be incomplete"))
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                    format!("deserialize Packet error: {:?}", e)))
            },
            IResult::Done(_, packet) => {
                buf.split_to(consumed);
                Ok(Some(packet))
            }
        }
    }
}

impl<'secure_channel> Encoder for Codec<'secure_channel> {
    type Item = Packet;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut stack_buf = [0; 2050];
        // serialize Packet
        let (_, packet_size) = try!( packet.to_bytes((&mut stack_buf, 0))
            .map_err(|e| Error::new(ErrorKind::Other,
                format!("Packet serialize error: {:?}", e)))
        );

        // encrypt it
        let encrypted = self.channel.encrypt(&stack_buf[..packet_size]);

        // create EncryptedPacket
        let encrypted_packet = EncryptedPacket { payload: encrypted };

        // serialize EncryptedPacket to binary form
        let (_, encrypted_packet_size) = try!( encrypted_packet.to_bytes((&mut stack_buf, 0))
            .map_err(|e| Error::new(ErrorKind::Other,
                format!("EncryptedPacket serialize error: {:?}", e)))
        );
        buf.extend_from_slice(&stack_buf[..encrypted_packet_size]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ::toxcore::crypto_core::*;
    use ::toxcore::tcp::codec::*;

    fn create_channels() -> (Channel, Channel) {
        let alice_session = Session::new();
        let bob_session = Session::new();

        // assume we got Alice's PK & Nonce via handshake
        let alice_pk = *alice_session.pk();
        let alice_nonce = *alice_session.nonce();

        // assume we got Bob's PK & Nonce via handshake
        let bob_pk = *bob_session.pk();
        let bob_nonce = *bob_session.nonce();

        // Now both Alice and Bob may create secure Channels
        let alice_channel = Channel::new(alice_session, &bob_pk, &bob_nonce);
        let bob_channel = Channel::new(bob_session, &alice_pk, &alice_nonce);

        (alice_channel, bob_channel)
    }

    fn check_packet(buf: &mut BytesMut, alice_codec: &mut Codec, bob_codec: &mut Codec, packet: Packet) {
        alice_codec.encode(packet.clone(), buf).expect("Alice should encode");
        let res = bob_codec.decode(buf).unwrap().expect("Bob should decode");
        assert_eq!(packet, res);

        bob_codec.encode(packet.clone(), buf).expect("Bob should encode");
        let res = alice_codec.decode(buf).unwrap().expect("Alice should decode");
        assert_eq!(packet, res);
    }

    #[test]
    fn encode_decode() {
        let (pk, _) = gen_keypair();
        let (alice_channel, bob_channel) = create_channels();
        let mut buf = BytesMut::new();
        let mut alice_codec = Codec { channel: &alice_channel };
        let mut bob_codec = Codec { channel: &bob_channel };

        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::RouteRequest( RouteRequest { peer_pk: pk } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::RouteResponse( RouteResponse { connection_id: 42, pk: pk } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::ConnectNotification( ConnectNotification { connection_id: 42 } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::DisconnectNotification( DisconnectNotification { connection_id: 42 } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::PingRequest( PingRequest { ping_id: 4242 } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::PongResponse( PongResponse { ping_id: 4242 } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::OobSend( OobSend { destination_pk: pk, data: vec![13; 42] } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::OobReceive( OobReceive { sender_pk: pk, data: vec![13; 24] } ) );
        check_packet(&mut buf, &mut alice_codec, &mut bob_codec, Packet::Data( Data { connection_id: 42, data: vec![13; 2] } ) );
    }
}
