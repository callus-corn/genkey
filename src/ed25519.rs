use rand::prelude::*;
use crate::der::{TLV, Tag, DER};

// RFC 8410 section 7
// CurvePrivateKey ::= OCTET STRING
pub struct Ed25519 {
    private_key: [u8; 32],
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
        let mut private_key: [u8; 32] = [0; 32];
        let mut rng = rand::thread_rng();
        for i in 0..private_key.len() {
            private_key[i] = rng.gen();
        }
        Ed25519{
            private_key
        }
    }
}

impl DER for Ed25519 {
    fn der(&self) -> Vec<u8> {
        TLV::new(Tag::OctetString, self.private_key.to_vec()).der()
    }
}
