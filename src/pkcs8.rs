use crate::der::{TLV, Tag, DER};

// RFC 5958 section 2 (PKCS #8)
// OneAsymmetricKey ::= SEQUENCE {
//   version INTEGER
//   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
//   privateKey OCTET STRING
//   OPTIONAL
// }
pub struct PKCS8 {
    version: u8,
    private_key_algorithm: Vec<u8>,
    private_key: Vec<u8>,
}

impl PKCS8 {
    pub const V1: u8 = 0;
    pub fn new(version: u8, private_key_algorithm: Vec<u8>, private_key: Vec<u8>) -> Self{
        PKCS8{
            version,
            private_key_algorithm,
            private_key,
        }
    }
}

impl DER for PKCS8 {
    fn der(&self) -> Vec<u8> {
        let mut value = vec![];
        value.extend(TLV::new(Tag::Integer, vec![self.version]).der());
        value.extend(self.private_key_algorithm.clone());
        value.extend(TLV::new(Tag::OctetString, self.private_key.clone()).der());

        TLV::new(Tag::Sequence, value).der()
    }
}
