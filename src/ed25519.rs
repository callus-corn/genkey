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
        let public_key = vec![0x16,0x4f,0xc2,0x8e,0xd6,0x38,0xd1,0x54,0xf5,0xd0,0x27,0x03,0xc4,0xd5,0xc1,0x77,0xe8,0xe4,0xde,0x98,0x59,0x3e,0x17,0x08,0x99,0xc4,0x7f,0x92,0xea,0xd5,0xac,0x25];
        let mut out = Vec::new();
        out.extend(SSH::to_string(b"ssh-ed25519"));
        out.extend(SSH::to_string(&public_key));

        out
    }

    fn gen_ssh_private_key(&self, checkint: Vec<u8>) -> Vec<u8> {
        let public_key = vec![0x16,0x4f,0xc2,0x8e,0xd6,0x38,0xd1,0x54,0xf5,0xd0,0x27,0x03,0xc4,0xd5,0xc1,0x77,0xe8,0xe4,0xde,0x98,0x59,0x3e,0x17,0x08,0x99,0xc4,0x7f,0x92,0xea,0xd5,0xac,0x25];
        let mut ssh_private_key = self.private_key.clone();
        ssh_private_key.extend(public_key.clone());

        let mut out = Vec::new();
        out.extend(checkint.clone());
        out.extend(checkint);
        out.extend(SSH::to_string(b"ssh-ed25519"));
        out.extend(SSH::to_string(&public_key));
        out.extend(SSH::to_string(&ssh_private_key));
        out.extend(SSH::to_string(b"yamazaki@MyComputer"));
        for i in 1..8 {
            if out.len() % 8 == 0 {
                break;
            }
            out.push(i as u8);
        }

        out
    }
}
