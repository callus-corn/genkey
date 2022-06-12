use num_bigint::{BigUint, BigInt, Sign, RandBigInt};
use num_traits::{One, Zero};
use crate::der::{TLV, Tag, DER};

// RFC 8017 Appendix A
// RSAPrivateKey ::= SEQUENCE {
//   version           Version,
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER,  -- e RSA public exponent
//   privateExponent   INTEGER,  -- d RSA private exponent
//   prime1            INTEGER,  -- p first two prime factors of the RSA modulus n
//   prime2            INTEGER,  -- q first two prime factors of the RSA modulus n
//   exponent1         INTEGER,  -- d mod (p-1)
//   exponent2         INTEGER,  -- d mod (q-1)
//   coefficient       INTEGER,  -- (inverse of q) mod p
//   otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }
pub struct RSA2048 {
    version: u8,
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    exponent1: Vec<u8>,
    exponent2: Vec<u8>,
    coefficient: Vec<u8>,
}

impl RSA2048 {
    // RFC 8017 Appendix C
    // AlgorithmIdentifier ::= {
    //   SEQUENCE {
    //     algorithm OBJECT IDENTIFIER
    //     parameters OPTIONAL
    //   }
    // }
    // RFC 8017 Appendix C
    // rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1 }
    // pkcs-1 OBJECT IDENTIFIER ::= { 1.2.840.113549.1.1 }
    // Parameters field shall have a value of type NULL
    pub const ID: [u8; 15] = [0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00];

    pub fn new() -> Self {
        let version = 0;
        let e = BigInt::from_signed_bytes_be(&[0x01,0x00,0x01]);

        let mut rng = rand::thread_rng();
        let low = BigUint::parse_bytes(b"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",16).unwrap();
        let hight = low.clone() << 1;
        let mut p = rng.gen_biguint_range(&low, &hight);
        while !is_prime(&p) {
            p = rng.gen_biguint_range(&low, &hight);
        }
        let p = BigInt::from_biguint(Sign::Plus, p);
        let mut q = rng.gen_biguint_range(&low, &hight);
        while !is_prime(&q) {
            q = rng.gen_biguint_range(&low, &hight);
        }
        let q = BigInt::from_biguint(Sign::Plus, q);

        let n = &p*&q;
        let d = inv(&e,&((&p - 1u8) * (&q - 1u8))).0;
        let exponent1 = &d % (&p - 1u8);
        let exponent2 = &d % (&q - 1u8);
        let coefficient = inv(&q,&p).0;

        let n = to_vec_util(n);
        let e = to_vec_util(e);
        let d = to_vec_util(d);
        let p = to_vec_util(p);
        let q = to_vec_util(q);
        let exponent1 = to_vec_util(exponent1);
        let exponent2 = to_vec_util(exponent2);
        let coefficient = to_vec_util(coefficient);

        RSA2048{
            version,
            n,
            e,
            d,
            p,
            q,
            exponent1,
            exponent2,
            coefficient,
        }
    }
}

impl DER for RSA2048 {
    fn der(&self) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend(TLV::new(Tag::Integer, vec![self.version]).der());
        value.extend(TLV::new(Tag::Integer, self.n.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.e.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.d.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.p.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.q.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.exponent1.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.exponent2.clone()).der());
        value.extend(TLV::new(Tag::Integer, self.coefficient.clone()).der());

        TLV::new(Tag::Sequence, value).der()
    }
}

fn inv(a: &BigInt, b:&BigInt) -> (BigInt, BigInt) {
    if *b == BigInt::zero() {
        return (BigInt::one(), BigInt::zero());
    }
    let d = inv(b, &(a%b));
    let x = d.1;
    let y = d.0 - (a/b)*&x;
    (x, y)
}

const SMALL_PRIMES: [u32; 168] = [
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
	101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
	197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
	311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
	431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
	557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
	661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
	809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
	937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
];

fn is_prime(n: &BigUint) -> bool {
    let zero: BigUint = BigUint::zero();
    let one: BigUint = BigUint::one();
    let two = BigUint::from_bytes_be(&[2]);
    for i in SMALL_PRIMES.iter() {
        if n % i == zero {
            return false;
        }
    }

    let mut k = 0;
    let mut d = n - 1u8;
    while &d % 2u8 == zero {
        k = k + 1;
        d = &d >> 1;
    }
    let mut rng = rand::thread_rng();
    'Miller_Rabin: for _ in 0..64 {
        let a = rng.gen_biguint_range(&two, &(n - 2u8));
        let mut b = a.modpow(&d, n);
        if b == one {
            continue;
        }
        for _ in 0..k {
            if b == n - 1u8 {
                continue 'Miller_Rabin;
            }
            b = b.modpow(&two, n);
        }
        return false
    }
    true
}

fn to_vec_util(x: BigInt) -> Vec<u8> {
    let mut out = Vec::new();
    let x = x.to_bytes_be().1;
    if x[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend(x);
    out
}
