use sha256::digest;
use secp256k1::SecretKey;
use colored::Colorize;
use bitcoin::{
    PublicKey,
    PrivateKey,
    secp256k1::Secp256k1,
    Address,
    Network,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    password: String,
}

fn priv_key(pass: &str) -> String {
    digest(pass)
}

fn btc_address(priv_key: &str) -> Address {
    // generate internal secret key:
    let secret_key = SecretKey::from_slice(
        &hex::decode(&priv_key)
            .expect("Not valid hex!")
        ).expect("Expected 32bytes as private key");
    
    // generate private key wrapper struct from secret key:
    let private_key = PrivateKey::new(
        secret_key,
        Network::Bitcoin
    );

    // generate the public key and create a bitcoin address from the public key
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_private_key(&secp, &private_key);
    Address::p2pkh(&public_key, Network::Bitcoin)
}

fn main() {
    let args = Args::parse();

    // generate a private key from a password:
    let p_key = priv_key(&args.password);
    println!("Private Key:\n[{}]", p_key.yellow().bold());

    let address = btc_address(&p_key);
    println!("Bitcoin Address:\n[{}]", address.to_string().blue().bold());
}
