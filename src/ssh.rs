use crate::pem::PEM;

pub trait SSHEncode{
    fn gen_ssh_public_key(&self) -> Vec<u8>;
    fn gen_ssh_private_key(&self) -> Vec<u8>;
}

pub struct SSH{
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl SSH {
    // "openssh-key-v1\0"
    const AUTH_MAGIC: [u8; 15] = [0x6f,0x70,0x65,0x6e,0x73,0x73,0x68,0x2d,0x6b,0x65,0x79,0x2d,0x76,0x31,0x00];

    pub fn new(key: &dyn SSHEncode) -> Self {
        let public_key = key.gen_ssh_public_key();
        let private_key = key.gen_ssh_private_key();
        SSH {
            public_key,
            private_key,
        }
    }

    pub fn to_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = bytes.len();
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.extend(bytes);
    
        out
    }

    fn dump(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(SSH::AUTH_MAGIC.to_vec());
        out.extend(SSH::to_string(b"none"));
        out.extend(SSH::to_string(b"none"));
        out.extend(SSH::to_string(b""));
        out.extend([0x00,0x00,0x00,0x01]);
        out.extend(SSH::to_string(&self.public_key.clone()));
        out.extend(SSH::to_string(&self.private_key.clone()));

        out
    }
}

impl PEM for SSH {
    fn base64(&self) -> Vec<u8> {
        let dump = self.dump();
        let base64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = Vec::new();
        // 8 8 8 bit -> 6 6 6 6 bit
        for i in 0..(dump.len()/3) {
            encoded.push(base64_table[(dump[i*3]>>2) as usize]);
            encoded.push(base64_table[(((dump[i*3]&0b11)<<4)|(dump[i*3+1]>>4)) as usize]);
            encoded.push(base64_table[(((dump[i*3+1]&0b1111)<<2)|(dump[i*3+2]>>6)) as usize]);
            encoded.push(base64_table[(dump[i*3+2]&0b111111) as usize]);
        }
        // 8 8 bit -> 6 6 4 bit + 0b00 + '='
        if dump.len() % 3 == 2 {
            encoded.push(base64_table[(dump[dump.len()-2]>>2) as usize]);
            encoded.push(base64_table[(((dump[dump.len()-2]&0b11)<<4)|(dump[dump.len()-1]>>4)) as usize]);
            encoded.push(base64_table[((dump[dump.len()-1]&0b1111)<<2) as usize]);
            encoded.push('=' as u8);
        }
        // 8 bit -> 6 2 bit + 0b0000 + '=' + '='
        if dump.len() % 3 == 1 {
            encoded.push(base64_table[(dump[dump.len()-1]>>2) as usize]);
            encoded.push(base64_table[((dump[dump.len()-1]&0b11)<<4) as usize]);
            encoded.push('=' as u8);
            encoded.push('=' as u8);
        }

        let mut out = Vec::new();
        for i in 0..encoded.len() {
            if i > 0 && i % 70 == 0 {
                out.extend(b"\n");
            }
            out.push(encoded[i]);
        }
    
        out
    }

    fn pem(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(b"-----BEGIN OPENSSH PRIVATE KEY-----\n");
        out.extend(self.base64());
        out.extend(b"\n-----END OPENSSH PRIVATE KEY-----\n");
        
        out
    }
}
