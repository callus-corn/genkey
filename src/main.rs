use std::fs::File;
use std::io::{stdout, Write};
use clap::{Parser, ArgEnum};
use genkey::{DER, PEM, PKCS8, Ed25519, RSA2048};

#[derive(Parser)]
#[clap(
    name = "genkey",
    author = "Yamazaki Mitsufumi",
    version = "v1.0.0",
    about = "generate key of rsa or ed25519"
)]
struct Args {
    //filename to save the key
    #[clap(short, long)]
    file: Option<String>,

    //key type. rsa or ed25519
    #[clap(short = 't', long = "type", arg_enum, default_value = "rsa")]
    algorithm: Algorithm,

    //key format. pkcs8 or ssh
    #[clap(short = 'u', long = "use", arg_enum, default_value = "ssh")]
    format: Format,
}

#[derive(ArgEnum, Clone)]
enum Algorithm {
    RSA,
    Ed25519,
}

#[derive(ArgEnum, Clone)]
enum Format {
    SSH,
    TLS,
}

fn main() {
    let args = Args::parse();

    let out = match (args.format, args.algorithm) {
        (Format::SSH, Algorithm::RSA) => RSA2048::new().der().pem(),
        (Format::SSH, Algorithm::Ed25519) => PKCS8::new(PKCS8::V1, Ed25519::ID.to_vec(), Ed25519::new().der()).der().pem(),
        (Format::TLS, Algorithm::RSA) => PKCS8::new(PKCS8::V1, RSA2048::ID.to_vec(), RSA2048::new().der()).der().pem(),
        (Format::TLS, Algorithm::Ed25519) => PKCS8::new(PKCS8::V1, Ed25519::ID.to_vec(), Ed25519::new().der()).der().pem(),
    };

    match args.file {
        Some(x) => File::create(x).unwrap().write_all(&out).unwrap(),
        None => stdout().write_all(&out).unwrap(),
    };
}
