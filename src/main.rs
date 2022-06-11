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
    //file to save the key
    #[clap(short, long)]
    file: Option<String>,

    //key type
    #[clap(short, long, arg_enum, default_value = "rsa")]
    algorithm: Algorithm
}

#[derive(ArgEnum, Clone)]
enum Algorithm {
    RSA,
    Ed25519,
}

fn main() {
    let args = Args::parse();

    let pkcs8 = match args.algorithm {
        Algorithm::RSA => (PKCS8::V1, RSA2048::ID.to_vec(), RSA2048::new().der()),
        Algorithm::Ed25519 => (PKCS8::V1, Ed25519::ID.to_vec(), Ed25519::new().der()),
    };
    let pem = PKCS8::new(pkcs8).der().pem();

    match args.file {
        Some(x) => File::create(x).unwrap().write_all(&pem).unwrap(),
        None => stdout().write_all(&pem).unwrap(),
    }
}
