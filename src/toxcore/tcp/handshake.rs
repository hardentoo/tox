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

/*! Handshake packets to establish a confirmed connection via
handshake using [`Diagram`](https://zetok.github.io/tox-spec/#handshake-diagram)

*/

use toxcore::crypto_core::*;
use toxcore::binary_io::*;

/** The request of the client to create a TCP handshake.

According to https://zetok.github.io/tox-spec/#handshake-request.

Serialized form:

Length  | Contents
------- | --------
`32`    | PK of the client
`24`    | Nonce of the encrypted payload
`72`    | Encrypted payload (plus MAC)

*/

pub struct Client {
    /// Client's Public Key
    pub pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload according to
    /// https://zetok.github.io/tox-spec/#handshake-request-packet-payload
    pub payload: Vec<u8>
}

from_bytes!(Client, do_parse!(
    pk: call!(PublicKey::parse_bytes) >>
    nonce: call!(Nonce::parse_bytes) >>
    payload: take!(72) >>
    (Client { pk: pk, nonce: nonce, payload: payload.to_vec() })
));

to_bytes!(Client, result, self {
    result.extend_from_slice(self.pk.as_ref());
    result.extend_from_slice(self.nonce.as_ref());
    result.extend_from_slice(self.payload.as_ref());
});

/** The response of the server to a TCP handshake.

According to https://zetok.github.io/tox-spec/#handshake-response.

Serialized form:

Length  | Contents
------- | --------
`24`    | Nonce for the encrypted payload
`72`    | Encrypted payload (plus MAC)

*/

pub struct Server {
    /// Nonce of the encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload according to
    /// https://zetok.github.io/tox-spec/#handshake-response-payload.
    pub payload: Vec<u8>
}

from_bytes!(Server, do_parse!(
    nonce: call!(Nonce::parse_bytes) >>
    payload: take!(72) >>
    (Server { nonce: nonce, payload: payload.to_vec() })
));

to_bytes!(Server, result, self {
    result.extend_from_slice(self.nonce.as_ref());
    result.extend_from_slice(self.payload.as_ref());
});

/** The payload of a TCP handshake. The payload is encrypted with algo:

precomputed_key = precomputed(self_pk, other_sk)
encrypted_payload = encrypt_data_symmetric(precomputed_key, nonce, payload)

According to https://zetok.github.io/tox-spec/#handshake-request-packet-payload
or https://zetok.github.io/tox-spec/#handshake-response-payload

Serialized and decrypted form:

Length  | Contents
------- | --------
`32`    | PublicKey for the current session
`24`    | Nonce of the current session

*/

pub struct Payload {
    /// Temporary Session PK
    pub session_pk: PublicKey,
    /// Temporary Session Nonce
    pub session_nonce: Nonce
}

from_bytes!(Payload, do_parse!(
    pk: call!(PublicKey::parse_bytes) >>
    nonce: call!(Nonce::parse_bytes) >>
    (Payload { session_pk: pk, session_nonce: nonce })
));

to_bytes!(Payload, result, self {
    result.extend_from_slice(self.session_pk.as_ref());
    result.extend_from_slice(self.session_nonce.as_ref());
});
