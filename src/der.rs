#[allow(dead_code)]
pub enum Tag {
    Integer,
    OctetString,
    Null,
    ObjectIdentifier,
    Sequence,
}

pub struct TLV {
    tag: u8,
    length: Vec<u8>,
    value: Vec<u8>,
}

impl TLV {
    pub fn new(t: Tag, value: Vec<u8>) -> Self {
        let tag = match t {
            Tag::Integer => 0x02,
            Tag::OctetString => 0x04,
            Tag::Null => 0x05,
            Tag::ObjectIdentifier => 0x06,
            Tag::Sequence => 0x30,
        };

        let mut length = Vec::new();
        let l = value.len();
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

        TLV {
            tag,
            length,
            value,
        }
    }
}

pub trait DER {
    fn der(&self) -> Vec<u8>;
}

impl DER for TLV {
    fn der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.tag);
        out.extend(self.length.clone());
        out.extend(self.value.clone());
        out
    }
}
