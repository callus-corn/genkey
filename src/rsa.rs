use num_bigint::{BigUint, BigInt, Sign, RandBigInt};
use num_traits::{One, Zero};
use crate::der;
use crate::der::{Tag, DerEncode};
use crate::ssh;
use crate::ssh::SshFormat;
use crate::pkcs8::Pkcs8Format;
use crate::pem::{base64, PemEncode};

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
pub struct Rsa2048 {
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

impl Rsa2048 {
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
    const VERSION: u8 = 0;
    const E: [u8; 3] = [0x01,0x00,0x01];

    pub fn new() -> Self {
        let version = Rsa2048::VERSION;
        let e = BigUint::from_bytes_be(&Rsa2048::E);

        let mut rng = rand::thread_rng();
        let low = BigUint::parse_bytes(b"c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",16).unwrap();
        let hight = BigUint::parse_bytes(b"10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",16).unwrap();

        let mut p = rng.gen_biguint_range(&low, &hight);
        while !is_prime(&p) {
            p = rng.gen_biguint_range(&low, &hight);
        }
        let mut q = rng.gen_biguint_range(&low, &hight);
        while !is_prime(&q) {
            q = rng.gen_biguint_range(&low, &hight);
        }

        let n = &p*&q;
        let d = inv(&e, &((&p - 1u8) * (&q - 1u8)));
        let exponent1 = &d % (&p - 1u8);
        let exponent2 = &d % (&q - 1u8);
        let coefficient = inv(&q, &p) % &p;

        let n = n.to_bytes_be();
        let e = e.to_bytes_be();
        let d = d.to_bytes_be();
        let p = p.to_bytes_be();
        let q = q.to_bytes_be();
        let exponent1 = exponent1.to_bytes_be();
        let exponent2 = exponent2.to_bytes_be();
        let coefficient = coefficient.to_bytes_be();

        Rsa2048{
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

    pub fn from_private_key(p: Vec<u8>, q: Vec<u8>) -> Self {
        let version = Rsa2048::VERSION;
        let e = BigUint::from_bytes_be(&Rsa2048::E);

        let p = BigUint::from_bytes_be(&p);
        let q = BigUint::from_bytes_be(&q);
        let n = &p*&q;
        let d = inv(&e,&((&p - 1u8) * (&q - 1u8)));
        let exponent1 = &d % (&p - 1u8);
        let exponent2 = &d % (&q - 1u8);
        let coefficient = inv(&q,&p) % &p;

        let n = der::to_integer(n.to_bytes_be());
        let e = der::to_integer(e.to_bytes_be());
        let d = der::to_integer(d.to_bytes_be());
        let p = der::to_integer(p.to_bytes_be());
        let q = der::to_integer(q.to_bytes_be());
        let exponent1 = der::to_integer(exponent1.to_bytes_be());
        let exponent2 = der::to_integer(exponent2.to_bytes_be());
        let coefficient = der::to_integer(coefficient.to_bytes_be());

        Rsa2048{
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

impl SshFormat for Rsa2048 {
    fn gen_public_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(ssh::to_string(b"ssh-rsa"));
        out.extend(ssh::to_string(&self.e.clone()));
        out.extend(ssh::to_string(&self.n.clone()));

        out
    }

    fn gen_private_key(&self, checkint: u32, comment: String) -> Vec<u8> {
        let checkint = checkint.to_be_bytes();
        let comment = comment.as_bytes().to_vec();

        let mut out = Vec::new();
        out.extend(checkint.clone());
        out.extend(checkint);
        out.extend(ssh::to_string(b"ssh-rsa"));
        out.extend(ssh::to_string(&self.n.clone()));
        out.extend(ssh::to_string(&self.e.clone()));
        out.extend(ssh::to_string(&self.d.clone()));
        out.extend(ssh::to_string(&self.coefficient.clone()));
        out.extend(ssh::to_string(&self.p.clone()));
        out.extend(ssh::to_string(&self.q.clone()));
        out.extend(ssh::to_string(&comment));
        for i in 1..8 {
            if out.len() % 8 == 0 {
                break;
            }
            out.push(i as u8);
        }

        out
    }
}

impl DerEncode for Rsa2048 {
    fn to_der(&self) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend(der::encode(Tag::Integer, vec![self.version]));
        value.extend(der::encode(Tag::Integer, self.n.clone()));
        value.extend(der::encode(Tag::Integer, self.e.clone()));
        value.extend(der::encode(Tag::Integer, self.d.clone()));
        value.extend(der::encode(Tag::Integer, self.p.clone()));
        value.extend(der::encode(Tag::Integer, self.q.clone()));
        value.extend(der::encode(Tag::Integer, self.exponent1.clone()));
        value.extend(der::encode(Tag::Integer, self.exponent2.clone()));
        value.extend(der::encode(Tag::Integer, self.coefficient.clone()));

        der::encode(Tag::Sequence, value)
    }
}

impl Pkcs8Format for Rsa2048 {
    fn gen_algorithm_identifier(&self) -> Vec<u8> {
        Rsa2048::ID.to_vec()
    }

    fn gen_private_key(&self) -> Vec<u8> {
        self.to_der()
    }
}

impl PemEncode for Rsa2048 {
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

fn inv(a: &BigUint, b:&BigUint) -> BigUint {
    let a = BigInt::from_biguint(Sign::Plus, a.clone());
    let b = BigInt::from_biguint(Sign::Plus, b.clone());
    let mut x = gcd(&a, &b).0;
    while x < BigInt::zero() {
        x = x + &b;
    }
    x.to_biguint().unwrap()
}

fn gcd(a: &BigInt, b:&BigInt) -> (BigInt, BigInt) {
    if *b == BigInt::zero() {
        return (BigInt::one(), BigInt::zero());
    }
    let d = gcd(b, &(a%b));
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
