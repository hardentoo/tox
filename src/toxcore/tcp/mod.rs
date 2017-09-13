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

use toxcore::crypto_core::*;
use toxcore::binary_io::*;

pub mod handshake;
pub mod secure;
pub mod packet;
pub mod codec;

// TODO split create_client_handshake, handle_client_handshake, handle_server_handshake
//        into more separated and reusable code


fn create_client_handshake(client_pk: &PublicKey,
                           client_sk: &SecretKey,
                           server_pk: &PublicKey) -> (secure::Session, handshake::Client) {
    let session = secure::Session::new();
    let payload = handshake::Payload { session_pk: *session.pk(), session_nonce: *session.nonce() };

    let precomputed = encrypt_precompute(server_pk, client_sk);
    let nonce = gen_nonce();
    let encrypted_payload = encrypt_data_symmetric(&precomputed, &nonce, &payload.to_bytes());

    let handshake = handshake::Client { pk: *client_pk, nonce: nonce, payload: encrypted_payload };
    (session, handshake)
}

fn handle_client_handshake(server_sk: &SecretKey,
                           client_handshake: handshake::Client) -> (secure::Channel, handshake::Server) {
    let precomputed = encrypt_precompute(&client_handshake.pk, server_sk);
    let payload_bytes = decrypt_data_symmetric(&precomputed, &client_handshake.nonce, &client_handshake.payload);
    let payload = handshake::Payload::from_bytes(&payload_bytes.unwrap()).unwrap();

    let client_pk = payload.session_pk;
    let client_nonce = payload.session_nonce;

    let session = secure::Session::new();
    let server_payload = handshake::Payload { session_pk: *session.pk(), session_nonce: *session.nonce() };
    let nonce = gen_nonce();
    let server_encrypted_payload = encrypt_data_symmetric(&precomputed, &nonce, &server_payload.to_bytes());

    let server_handshake = handshake::Server { nonce: nonce, payload: server_encrypted_payload };
    let channel = secure::Channel::new(session, &client_pk, &client_nonce);
    (channel, server_handshake)
}

fn handle_server_handshake(client_sk: &SecretKey,
                           server_pk: &PublicKey,
                           client_session: secure::Session,
                           server_handshake: handshake::Server) -> secure::Channel {
    let precomputed = encrypt_precompute(server_pk, client_sk);
    let payload_bytes = decrypt_data_symmetric(&precomputed, &server_handshake.nonce, &server_handshake.payload);
    let payload = handshake::Payload::from_bytes(&payload_bytes.unwrap()).unwrap();

    let server_pk = payload.session_pk;
    let server_nonce = payload.session_nonce;

    let channel = secure::Channel::new(client_session, &server_pk, &server_nonce);
    channel
}

#[cfg(test)]
mod tests {
    use ::toxcore::tcp::*;
    fn create_channels_with_handshake() -> (secure::Channel, secure::Channel) {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        // client creates a handshake packet
        let (client_session, client_handshake) = create_client_handshake(&client_pk, &client_sk, &server_pk);
        // sends it via network
        let client_handshake_bytes = client_handshake.to_bytes();
        // ..
        // .. network
        // ..
        // server receives a handshake packet
        let client_handshake = handshake::Client::from_bytes(&client_handshake_bytes).unwrap();
        // handles it & creates a secure Channel
        let (server_channel, server_handshake) = handle_client_handshake(&server_sk, client_handshake);
        // sends it via network
        let server_handshake_bytes = server_handshake.to_bytes();
        // ..
        // .. network
        // ..
        // client receives the reply
        let server_handshake = handshake::Server::from_bytes(&server_handshake_bytes).unwrap();
        // handles it & creates a secure Channel
        let client_channel = handle_server_handshake(&client_sk, &server_pk, client_session, server_handshake);
        // now they are ready to communicate via secure Channels
        (client_channel, server_channel)
    }
    #[test]
    fn test_secure_communication_with_handshake() {
        let (alice_channel, bob_channel) = create_channels_with_handshake();

        // And now they may communicate sending encrypted data to each other

        // Alice encrypts the message
        let alice_msg = "Hello Bob!";
        let alice_msg_encrypted = alice_channel.encrypt(alice_msg.as_bytes());
        assert_ne!(alice_msg.as_bytes().to_vec(), alice_msg_encrypted);
        // Alice sends it somehow

        // Bob receives and decrypts
        assert_eq!( alice_msg.as_bytes().to_vec(), bob_channel.decrypt(alice_msg_encrypted.as_ref()).unwrap() );

        // Now Bob encrypts his message
        let bob_msg = "Oh hello Alice!";
        let bob_msg_encrypted = bob_channel.encrypt(bob_msg.as_bytes());
        assert_ne!(bob_msg.as_bytes().to_vec(), bob_msg_encrypted);
        // And sends it back to Alice

        assert_eq!( bob_msg.as_bytes().to_vec(), alice_channel.decrypt(bob_msg_encrypted.as_ref()).unwrap() );
    }
}
