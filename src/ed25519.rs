use rand::prelude::*;
use crate::der::{TLV, Tag, DER};
use crate::ssh::{SSH, SSHEncode};

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

    pub fn new() -> Self {
        let mut private_key = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            private_key.push(rng.gen());
        }
        while private_key[0] < 0x80 {
            private_key[0] = rng.gen();
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
}

impl DER for Ed25519 {
    fn der(&self) -> Vec<u8> {
        TLV::new(Tag::OctetString, self.private_key.clone()).der()
    }
}

impl SSHEncode for Ed25519 {
    fn gen_ssh_public_key(&self) -> Vec<u8> {
        let public_key = vec![0x74,0x6a,0xb6,0x17,0xd5,0xc8,0xd6,0x87,0x6a,0xb8,0x0b,0x60,0xfc,0xa6,0x26,0xb3,0xf8,0x36,0x7f,0x7d,0xf7,0x2a,0x82,0x87,0xe5,0xa5,0xe6,0xa8,0xf8,0x1f,0x51,0x07];
        let mut out = Vec::new();
        out.extend(SSH::to_string(b"ssh-ed25519"));
        out.extend(SSH::to_string(&public_key));

        out
    }

    fn gen_ssh_private_key(&self, checkint: Vec<u8>) -> Vec<u8> {
        let public_key = vec![0x74,0x6a,0xb6,0x17,0xd5,0xc8,0xd6,0x87,0x6a,0xb8,0x0b,0x60,0xfc,0xa6,0x26,0xb3,0xf8,0x36,0x7f,0x7d,0xf7,0x2a,0x82,0x87,0xe5,0xa5,0xe6,0xa8,0xf8,0x1f,0x51,0x07];
        let mut ssh_private_key = self.private_key.clone();
        ssh_private_key.extend(public_key.clone());

        let mut out = Vec::new();
        out.extend(checkint.clone());
        out.extend(checkint);
        out.extend(SSH::to_string(b"ssh-ed25519"));
        out.extend(SSH::to_string(&public_key));
        out.extend(SSH::to_string(&ssh_private_key));
        out.extend(SSH::to_string(b""));
        for i in 1..8 {
            if out.len() % 8 == 0 {
                break;
            }
            out.push(i as u8);
        }

        out
    }
}
