use std::fs::File;
use std::io::{stdout, Write};
use clap::{Parser, ArgEnum};
use genkey::{PemEncode, Pkcs8, Ssh, Ed25519, Rsa2048};

#[derive(Parser)]
#[clap(
    name = "genkey",
    author = "Yamazaki Mitsufumi",
    version = "v1.0.0",
    about = "generate key of rsa or ed25519"
)]
struct Args {
    //key name and file name.
    #[clap(short, long)]
    name: Option<String>,

    //key algorithm. rsa or ed25519.
    #[clap(short, long, arg_enum, default_value = "rsa")]
    algorithm: Algorithm,

    //key format. ssh or pkcs8.
    #[clap(short, long, arg_enum, default_value = "ssh")]
    format: Format,

    //comment for ssh key.
    #[clap(short, long, default_value = "")]
    comment: String,
}

#[derive(ArgEnum, Clone)]
enum Algorithm {
    Rsa,
    Ed25519,
}

#[derive(ArgEnum, Clone)]
enum Format {
    Ssh,
    Pkcs8,
}

fn main() {
    let args = Args::parse();

    let out = match (args.format, args.algorithm) {
        (Format::Ssh, Algorithm::Rsa) => Ssh::new(&Rsa2048::new(), args.comment).to_pem(),
        (Format::Ssh, Algorithm::Ed25519) => Ssh::new(&Ed25519::new(), args.comment).to_pem(),
        (Format::Pkcs8, Algorithm::Rsa) => Pkcs8::new(Pkcs8::V1, &Rsa2048::new()).to_pem(),
        (Format::Pkcs8, Algorithm::Ed25519) => Pkcs8::new(Pkcs8::V1, &Ed25519::new()).to_pem(),
    };

    match args.name {
        Some(x) => File::create(x).unwrap().write_all(&out).unwrap(),
        None => stdout().write_all(&out).unwrap(),
    };
}
