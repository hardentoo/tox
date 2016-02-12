/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

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

//! Tests for the DHT module.

//#![cfg(test)]

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::*;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use ip::IpAddr;
use quickcheck::quickcheck;


// PackedNode::

// TODO: finish writing test; include:
//  * assert whether IP matches
//  * assert whether PK matches

// ::new()

#[test]
#[allow(non_snake_case)]
// TODO: when `::new()` will be able to fail, this test should check for whether
// it works/fails when needed;
// e.g. `IpType::UdpIpv4` and supplied `SocketAddr:V6(_)` should fail
fn packed_node_new_test_ip_type_UDP_IPv4() {
    let info = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());
    assert_eq!(IpType::UdpIpv4, info.ip_type);
}


// ::ip()

#[test]
fn packed_node_ip_test() {
    let ipv4 = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:0").unwrap()),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv4.ip() {
        IpAddr::V4(_) => {},
        IpAddr::V6(_) => panic!("This should not have happened, since IPv4 was supplied!"),
    }

    let ipv6 = PackedNode::new(IpType::UdpIpv6,
                               SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(),
                                   0, 0, 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv6.ip() {
        IpAddr::V4(_) => panic!("This should not have happened, since IPv6 was supplied!"),
        IpAddr::V6(_) => {},
    }
}


// ::as_bytes()

// TODO: tests for `::as_bytes()` should include:
// * tests for various ports with both IPv4 and IPv6 – can be done, but easily
//   only with same hardcoded IPv{4,6}, since quickcheck ↑
// * tests for various PKs - quickcheck doesn't support supplying more than 4
//   function arguments
//    - this requires a workaround with loops and hops - i.e. supply to the
//      quickcheck 4 `u64` arguments, cast to arrays, put elements from arrays
//      into a single vec and use vec to create PK
//
// Each test ↑ should have all possible types of `IpType`

/// Returns all possible variants of `PackedNode` `ip_type`, in order
/// listed by `IpType` enum.
fn packed_node_all_ip_types(saddr: SocketAddr, pk: &PublicKey)
    -> (PackedNode, PackedNode, PackedNode, PackedNode)
{
    let u4 = PackedNode::new(IpType::UdpIpv4, saddr, pk);
    let u6 = PackedNode::new(IpType::UdpIpv6, saddr, pk);
    let t4 = PackedNode::new(IpType::TcpIpv4, saddr, pk);
    let t6 = PackedNode::new(IpType::TcpIpv6, saddr, pk);
    (u4, u6, t4, t6)
}

#[test]
// tests for various IPv4 – use quickcheck
fn packed_node_as_bytes_test_ipv4() {
    fn with_random_ip(a: u8, b: u8, c: u8, d: u8) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
        let saddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), 1));
        let (u4, _, t4, _) = packed_node_all_ip_types(saddr, pk);
        // check whether ip_type variant matches
        assert!(u4.as_bytes()[0] == 2);
        assert!(t4.as_bytes()[0] == 130);

        // check whether IP matches ..
        //  ..with UDP
        assert!(u4.as_bytes()[1] == a);
        assert!(u4.as_bytes()[2] == b);
        assert!(u4.as_bytes()[3] == c);
        assert!(u4.as_bytes()[4] == d);
        //  ..with TCP
        assert!(t4.as_bytes()[1] == a);
        assert!(t4.as_bytes()[2] == b);
        assert!(t4.as_bytes()[3] == c);
        assert!(t4.as_bytes()[4] == d);

        // check whether length matches
        assert!(u4.as_bytes().len() == 39);
        assert!(t4.as_bytes().len() == 39);
    }
    quickcheck(with_random_ip as fn(u8, u8, u8, u8));
}

#[test]
// test for various IPv6 – quickckeck currently doesn't seem to have
// needed functionality, as it would require from quickcheck support for
// more than 4 function arguments
//  - this requires a workaround with loops and hops - i.e. supply to the
//    quickcheck a function that takes 2 `u64` arguments, convert those
//    numbers to arrays, and use numbers from arrays to do the job
fn packed_node_as_bytes_test_ipv6() {
    fn u64_as_u16s(num: u64) -> (u16, u16, u16, u16) {
        let mut array: [u16; 4] = [0; 4];
        for n in 0..array.len() {
            array[n] = (num >> (16 * n)) as u16;
        }
        let (a, b, c, d) = (array[0], array[1], array[2], array[3]);
        (a, b, c, d)
    }

    // slice to array. hopefully supplied slice is at least 2 bytes long.
    // uses only 2 first elements from slice.
    fn s_ar(slice: &[u8]) -> [u8; 2] {
        let mut array = [0; 2];
        for n in 0..2 {
            array[n] = slice[n];
        }
        array
    }


    fn with_random_ip(num1: u64, num2: u64, flowinfo: u32, scope_id: u32) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();

        let (a, b, c, d) = u64_as_u16s(num1);
        let (e, f, g, h) = u64_as_u16s(num2);
        let saddr = SocketAddr::V6(
                        SocketAddrV6::new(
                            Ipv6Addr::new(a, b, c, d, e, f, g, h),
                   /*port*/ 1, flowinfo, scope_id));
        let (_, u6, _, t6) = packed_node_all_ip_types(saddr, pk);
        // check whether ip_type variant matches
        assert!(u6.as_bytes()[0] == 10);
        assert!(t6.as_bytes()[0] == 138);

        // check whether IP matches ..
        //  ..with UDP
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[1..3])) == a);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[3..5])) == b);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[5..7])) == c);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[7..9])) == d);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[9..11])) == e);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[11..13])) == f);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[13..15])) == g);
        assert!(array_to_u16(&s_ar(&u6.as_bytes()[15..17])) == h);
        //  ..with TCP
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[1..3])) == a);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[3..5])) == b);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[5..7])) == c);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[7..9])) == d);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[9..11])) == e);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[11..13])) == f);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[13..15])) == g);
        assert!(array_to_u16(&s_ar(&t6.as_bytes()[15..17])) == h);

        // check whether length matches
        assert!(u6.as_bytes().len() == 51);
        assert!(t6.as_bytes().len() == 51);
    }
    quickcheck(with_random_ip as fn(u64, u64, u32, u32));
}
