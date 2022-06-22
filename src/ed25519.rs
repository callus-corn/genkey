use std::ops::Add;
use rand::prelude::*;
use num_bigint::{BigUint, BigInt, Sign};
use num_traits::{Zero, One};
use sha2::{Sha512, Digest};
use crate::der;
use crate::der::{Tag, DerEncode};
use crate::ssh;
use crate::ssh::SshFormat;
use crate::pkcs8::Pkcs8Format;

#[derive(Clone)]
struct Point {
    x: Vec<u8>,
    y: Vec<u8>,
}

impl Point{
    pub fn from_xy(x: Vec<u8>, y: Vec<u8>) -> Self {
        Point{
            x,
            y,
        }
    }
}

impl<'a, 'b> Add<&'b Point> for &'a Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        let p = BigUint::new(vec![2]).pow(255) - 19u32;
        let d = BigUint::from_bytes_be(&Ed25519::D);
        let x1 = BigUint::from_bytes_be(&self.x);
        let y1 = BigUint::from_bytes_be(&self.y);
        let x2 = BigUint::from_bytes_be(&other.x);
        let y2 = BigUint::from_bytes_be(&other.y);
        
        let tmp = d * &x1 * &x2 * &y1 * &y2 % &p;
        let x3 = (&x1 * &y2 + &x2 * &y1) * inv(&(1u32 + &tmp), &p) % &p;
        let y3 = (&y1 * &y2 + &x1 * &x2) * inv(&(1u32 + (&p - &tmp)), &p) % &p;

        let x = x3.to_bytes_be();
        let y = y3.to_bytes_be();

        Point{
            x,
            y,
        }
    }
}

// RFC 8410 section 7
// CurvePrivateKey ::= OCTET STRING
pub struct Ed25519 {
    private_key: Vec<u8>,
}

impl Ed25519 {
    // RFC 8017 Appendix C
    // AlgorithmIdentifier ::= {
    //   SEQUENCE {
    //     algorithm OBJECT IDENTIFIER
    //     parameters OPTIONAL
    //   }
    // }
    // RFC 8420 Appendix A.1
    // id-Ed25519 OBJECT IDENTIFIER ::= { 1.3.101.112 }
    // Parameters are absent.
    pub const ID: [u8; 7] = [0x30,0x05,0x06,0x03,0x2b,0x65,0x70];

    // 15112221349535400772501151409588531511454012693041857206046113283949847762202,
    // 46316835694926478169428394003475163141307993866256225615783033603165251855960,
    const B: ([u8; 32], [u8; 32]) = (
        [0x21,0x69,0x36,0xd3,0xcd,0x6e,0x53,0xfe,0xc0,0xa4,0xe2,0x31,0xfd,0xd6,0xdc,0x5c,0x69,0x2c,0xc7,0x60,0x95,0x25,0xa7,0xb2,0xc9,0x56,0x2d,0x60,0x8f,0x25,0xd5,0x1a],
        [0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x58],
    );

    // 37095705934669439343138083508754565189542113879843219016388785533085940283555
    const D: [u8; 32] = [0x52,0x03,0x6c,0xee,0x2b,0x6f,0xfe,0x73,0x8c,0xc7,0x40,0x79,0x77,0x79,0xe8,0x98,0x00,0x70,0x0a,0x4d,0x41,0x41,0xd8,0xab,0x75,0xeb,0x4d,0xca,0x13,0x59,0x78,0xa3];

    pub fn new() -> Self {
        let mut private_key = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            private_key.push(rng.gen());
        }
        Ed25519{
            private_key
        }
    }

    pub fn from_private_key(private_key: Vec<u8>) -> Self {
        Ed25519{
            private_key
        }
    }

    fn gen_public_key(&self) -> Vec<u8> {
        let x = Ed25519::B.0.to_vec();
        let y = Ed25519::B.1.to_vec();
        let b = Point::from_xy(x, y);
        let mut point = b.clone();
        let mut bin = Vec::new();

        let mut buffer = Sha512::new();
        buffer.update(self.private_key.clone());
        let buffer = &mut buffer.finalize()[..32];
        buffer[0] = buffer[0] & 0b1111_1000;
        buffer[31] = buffer[31] & 0b0111_1111 | 0b0100_0000;
        'to_bin: for (i, v) in buffer.iter().enumerate() {
            let mut byte = *v;
            for _ in 0..8 {
                if i == buffer.len() - 1 && byte == 1 {
                    break 'to_bin;
                }
                bin.push(byte % 2);
                byte = byte / 2;
            }
        }
        let bin: Vec<u8> = bin.iter().rev().map(|&s| s).collect();

        for v in bin.iter() {
            point = &point + &point;
            if *v == 1 {
                point = &point + &b;
            }
        }

        let mut out = point.y;
        out[0] = out[0] | ((point.x[31] & 1) << 7);

        out.iter().rev().map(|&s| s).collect()
    }

}

impl SshFormat for Ed25519 {
    fn gen_public_key(&self) -> Vec<u8> {
        let public_key = self.gen_public_key();

        let mut out = Vec::new();
        out.extend(ssh::to_string(b"ssh-ed25519"));
        out.extend(ssh::to_string(&public_key));

        out
    }

    fn gen_private_key(&self, checkint: u32, comment: String) -> Vec<u8> {
        let checkint = checkint.to_be_bytes();
        let comment = comment.as_bytes().to_vec();
        let public_key = self.gen_public_key();
        let mut ssh_private_key = self.private_key.clone();
        ssh_private_key.extend(public_key.clone());

        let mut out = Vec::new();
        out.extend(checkint.clone());
        out.extend(checkint);
        out.extend(ssh::to_string(b"ssh-ed25519"));
        out.extend(ssh::to_string(&public_key));
        out.extend(ssh::to_string(&ssh_private_key));
        out.extend(ssh::to_string(&comment));
        for i in 1..8 {
            if out.len() % 8 == 0 {
                break;
            }
            out.push(i as u8);
        }

        out
    }
}

impl DerEncode for Ed25519 {
    fn to_der(&self) -> Vec<u8> {
        der::encode(Tag::OctetString, self.private_key.clone())
    }
}

impl Pkcs8Format for Ed25519 {
    fn gen_algorithm_identifier(&self) -> Vec<u8> {
        Ed25519::ID.to_vec()
    }

    fn gen_private_key(&self) -> Vec<u8> {
        self.to_der()
    }
}

fn inv(a: &BigUint, b:&BigUint) -> BigUint {
    let a = BigInt::from_biguint(Sign::Plus, a.clone());
    let b = BigInt::from_biguint(Sign::Plus, b.clone());
    let mut x = gcd(&a, &b).0;
    while x < BigInt::zero() {
        x = x + &b;
    }
    x.to_biguint().unwrap()
}

fn gcd(a: &BigInt, b:&BigInt) -> (BigInt, BigInt) {
    if *b == BigInt::zero() {
        return (BigInt::one(), BigInt::zero());
    }
    let d = gcd(b, &(a%b));
    let x = d.1;
    let y = d.0 - (a/b)*&x;
    (x, y)
}
