use crate::der;
use crate::der::{Tag, DerEncode};
use crate::pem::{PemEncode, base64};

pub trait Pkcs8Format {
    fn gen_algorithm_identifier(&self) -> Vec<u8>;
    fn gen_private_key(&self) -> Vec<u8>;
}

pub struct Pkcs8 {
    version: u8,
    algorithm_identifier: Vec<u8>,
    private_key: Vec<u8>,
}

impl Pkcs8 {
    pub const V1: u8 = 0;

    pub fn new(version: u8, key: &dyn Pkcs8Format) -> Self {
        let algorithm_identifier = key.gen_algorithm_identifier();
        let private_key = key.gen_private_key();

        Pkcs8{
            version,
            algorithm_identifier,
            private_key,
        }
    }
}

// RFC 5958 section 2 (PKCS #8)
// OneAsymmetricKey ::= SEQUENCE {
//   version INTEGER
//   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
//   privateKey OCTET STRING
//   OPTIONAL
// }
impl DerEncode for Pkcs8 {
    fn to_der(&self) -> Vec<u8> {
        let mut value = vec![];
        value.extend(der::encode(Tag::Integer, vec![self.version]));
        value.extend(self.algorithm_identifier.clone());
        value.extend(der::encode(Tag::OctetString, self.private_key.clone()));

        der::encode(Tag::Sequence, value)
    }
}

impl PemEncode for Pkcs8 {
    fn to_pem(&self) -> Vec<u8> {
        let mut base64_with_linefeed = Vec::new();
        let base64 = base64(self.to_der());
        for i in 0..base64.len() {
            if i > 0 && i % 64 == 0 {
                base64_with_linefeed.extend(b"\n");
            }
            base64_with_linefeed.push(base64[i]);
        }

        let mut out = Vec::new();
        out.extend(b"-----BEGIN PRIVATE KEY-----\n");
        out.extend(base64_with_linefeed);
        out.extend(b"\n-----END PRIVATE KEY-----\n");
        
        out
    }
}