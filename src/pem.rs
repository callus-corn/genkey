pub trait PEM {
    // RFC 4648
    fn base64(&self) -> Vec<u8>;
    // RFC 5958 section 5
    fn pem(&self) -> Vec<u8>;
}

impl PEM for Vec<u8> {
    fn base64(&self) -> Vec<u8> {
        let base64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        // 8 8 8 bit -> 6 6 6 6 bit
        for i in 0..(self.len()/3) {
            if i > 0 && i % 16 == 0 {
                out.push('\n' as u8);
            }
            out.push(base64_table[(self[i*3]>>2) as usize]);
            out.push(base64_table[(((self[i*3]&0b11)<<4)|(self[i*3+1]>>4)) as usize]);
            out.push(base64_table[(((self[i*3+1]&0b1111)<<2)|(self[i*3+2]>>6)) as usize]);
            out.push(base64_table[(self[i*3+2]&0b111111) as usize]);
        }
        // 8 8 bit -> 6 6 4 bit + 0b00 + '='
        if self.len() % 3 == 2 {
            out.push(base64_table[(self[self.len()-2]>>2) as usize]);
            out.push(base64_table[(((self[self.len()-2]&0b11)<<4)|(self[self.len()-1]>>4)) as usize]);
            out.push(base64_table[((self[self.len()-1]&0b1111)<<2) as usize]);
            out.push('=' as u8);
        }
        // 8 bit -> 6 2 bit + 0b0000 + '=' + '='
        if self.len() % 3 == 1 {
            out.push(base64_table[(self[self.len()-1]>>2) as usize]);
            out.push(base64_table[((self[self.len()-1]&0b11)<<4) as usize]);
            out.push('=' as u8);
            out.push('=' as u8);
        }
    
        out
    }

    fn pem(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(b"-----BEGIN PRIVATE KEY-----\n");
        out.extend(self.base64());
        out.extend(b"\n-----END PRIVATE KEY-----\n");
        
        out
    }
}
