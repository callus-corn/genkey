// RFC 5958 section 5
pub trait PemEncode {
    fn to_pem(&self) -> Vec<u8>;
}

// RFC 4648
// no line feed
pub fn base64(data: Vec<u8>) -> Vec<u8> {
    let base64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    // 8 8 8 bit -> 6 6 6 6 bit
    for i in 0..(data.len()/3) {
        out.push(base64_table[(data[i*3]>>2) as usize]);
        out.push(base64_table[(((data[i*3]&0b11)<<4)|(data[i*3+1]>>4)) as usize]);
        out.push(base64_table[(((data[i*3+1]&0b1111)<<2)|(data[i*3+2]>>6)) as usize]);
        out.push(base64_table[(data[i*3+2]&0b111111) as usize]);
    }
    // 8 8 bit -> 6 6 4 bit + 0b00 + '='
    if data.len() % 3 == 2 {
        out.push(base64_table[(data[data.len()-2]>>2) as usize]);
        out.push(base64_table[(((data[data.len()-2]&0b11)<<4)|(data[data.len()-1]>>4)) as usize]);
        out.push(base64_table[((data[data.len()-1]&0b1111)<<2) as usize]);
        out.push('=' as u8);
    }
    // 8 bit -> 6 2 bit + 0b0000 + '=' + '='
    if data.len() % 3 == 1 {
        out.push(base64_table[(data[data.len()-1]>>2) as usize]);
        out.push(base64_table[((data[data.len()-1]&0b11)<<4) as usize]);
        out.push('=' as u8);
        out.push('=' as u8);
    }

    out
}
