use bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num::{FromPrimitive, Integer, One, ToPrimitive, Zero};
use std::{env, process, str::FromStr};
extern crate num;
extern crate num_bigint as bigint;
extern crate primal;
extern crate rand;

extern crate rsabench;
use rsabench::{gen_keys, KeySizeT};

fn main() {
    if std::env::args().len() != 2 {
        println!("Usage: ./rsa2048 <plaintext>");
        process::exit(1);
    }

    let args: Vec<String> = env::args().collect();

    let plaintext = &args[1];

    let key_size = 2048;
    let e = 65537;

    let (public_key, private_key) = gen_keys(
        KeySizeT::KeySize(key_size),
        rsabench::PublicExponentT::Exponent(e),
    );

    println!("\n\nRSA PUBLIC KEY ENCRYPTION");
    println!("\nPlaintext:            '{}'", plaintext);
    println!("* Private key is: {}", private_key);
    println!("* Public key is:  {}", public_key);

    let encrypted = public_key.encrypt(plaintext);

    println!("\nCiphertext:           '0x{}'", encrypted);
    let decrypted = private_key.decrypt(&encrypted);
    println!("\nDecrypted ciphertext: '{}'", decrypted);
}
