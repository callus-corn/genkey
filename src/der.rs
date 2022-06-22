#[allow(dead_code)]
pub enum Tag {
    Integer,
    OctetString,
    Null,
    ObjectIdentifier,
    Sequence,
}

pub trait DerEncode {
    fn to_der(&self) -> Vec<u8>;
}

pub fn encode(t: Tag, v: Vec<u8>) -> Vec<u8> {
    let tag = match t {
        Tag::Integer => 0x02,
        Tag::OctetString => 0x04,
        Tag::Null => 0x05,
        Tag::ObjectIdentifier => 0x06,
        Tag::Sequence => 0x30,
    };

    let mut length = Vec::new();
    let l = v.len();
    match l {
        0..=127 => length.push(l as u8),
        128..=255 => {
            length.push(0x81);
            length.push(l as u8);
        },
        256..=65535 => {
            length.push(0x82);
            length.push((l >> 8) as u8);
            length.push(l as u8);
        },
        _ => panic!("too long data"),
    }

    let value = v;

    let mut out = Vec::new();
    out.push(tag);
    out.extend(length);
    out.extend(value);

    out
}

pub fn to_integer(v: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    if v[0] >= 0x80 {
        out.push(0);
    }
    out.extend(v);

    out
}
