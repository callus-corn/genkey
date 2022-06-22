use rand::prelude::*;
use crate::pem::{PemEncode, base64};

pub trait SshFormat {
    fn gen_public_key(&self) -> Vec<u8>;
    fn gen_private_key(&self, checkint: u32, comment: String) -> Vec<u8>;
}

pub struct Ssh {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl Ssh {
    // "openssh-key-v1\0"
    const AUTH_MAGIC: [u8; 15] = [0x6f,0x70,0x65,0x6e,0x73,0x73,0x68,0x2d,0x6b,0x65,0x79,0x2d,0x76,0x31,0x00];
    // number of key is 1
    const NUMBER_OF_KEY: [u8; 4] = [0,0,0,1];

    pub fn new(key: &dyn SshFormat, comment: String) -> Self {
        let mut rng = rand::thread_rng();
        let checkint = rng.gen();
        let public_key = key.gen_public_key();
        let private_key = key.gen_private_key(checkint, comment);

        Ssh{
            public_key,
            private_key,
        }
    }

    pub fn with_checkint(key: &dyn SshFormat, comment: String, checkint: u32) -> Self {
        let public_key = key.gen_public_key();
        let private_key = key.gen_private_key(checkint, comment);

        Ssh{
            public_key,
            private_key,
        }
    }
}

// string: length_of_data data
// length_of_data: 32bit
pub fn to_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = data.len();
    out.push((len >> 24) as u8);
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend(data);

    out
}

// PROTOCOL.key
//
// byte[]  AUTH_MAGIC
// string  ciphername
// string  kdfname
// string  kdfoptions
// int     number of keys N
// string  publickey1
// string  publickey2
// ...
// string  publickeyN
// string  encrypted, padded list of private keys
impl PemEncode for Ssh {
    fn to_pem(&self) -> Vec<u8> {
        let mut dump = Vec::new();
        dump.extend(Ssh::AUTH_MAGIC.to_vec());
        // key encryption is not supported
        dump.extend(to_string(b"none"));
        dump.extend(to_string(b"none"));
        dump.extend(to_string(b""));
        dump.extend(Ssh::NUMBER_OF_KEY.to_vec());
        dump.extend(to_string(&self.public_key.clone()));
        dump.extend(to_string(&self.private_key.clone()));

        let base64 = base64(dump);
        let mut base64_with_linefeed = Vec::new();
        for i in 0..base64.len() {
            if i > 0 && i % 70 == 0 {
                base64_with_linefeed.extend(b"\n");
            }
            base64_with_linefeed.push(base64[i]);
        }

        let mut out = Vec::new();
        out.extend(b"-----BEGIN OPENSSH PRIVATE KEY-----\n");
        out.extend(base64_with_linefeed);
        out.extend(b"\n-----END OPENSSH PRIVATE KEY-----\n");
        
        out
    }
}
