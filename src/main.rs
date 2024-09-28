use std::fs::File;
use std::io::prelude::*;

use num_bigint::BigUint;
use num_traits::Num;
use rsa::{RSAKeyPair, RSAPublicKey, RSAPrivateKey};
use serde_json::Value;

mod rsa;

mod math_utils;

fn print_help() {
    println!("Usage:");
    println!("  'rsa gen <bit_width> <path>': Generate RSA key pair with specified bit with and pit it into <path>");
    println!("  'rsa enc <data_file> <pub_key>': Encrypt a file with public key");
    println!("  'rsa dec <data_file> <priv_key>': Decrypt a file with private key");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    if args[1] == "gen" {
        let rsa = RSAKeyPair::new(args[2].parse().unwrap(), args[4].parse().unwrap());

        let path = args[3].clone();
        
        let mut pub_key_file = File::create(path.clone() + "_public.json").unwrap();
        let mut priv_key_file = File::create(path.clone() + "_private.json").unwrap();

        pub_key_file.write_all(serde_json::to_string_pretty(&rsa.public_key).unwrap().as_bytes()).unwrap();
        priv_key_file.write_all(serde_json::to_string_pretty(&rsa.private_key).unwrap().as_bytes()).unwrap();
    } else if args[1] == "enc" {
        let data = BigUint::from_bytes_be(&args[3].as_bytes());

        let rsa_public_json: Value = serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();

        let public_key: RSAPublicKey = RSAPublicKey { 
            e: BigUint::from_str_radix(rsa_public_json["e"].as_str().unwrap(), 16).unwrap(), 
            n: BigUint::from_str_radix(rsa_public_json["n"].as_str().unwrap(), 16).unwrap()
        };

        let cypher = rsa::encrypt(&data, &public_key);
        println!("Encrypted message: '{}'", cypher.to_str_radix(16));
    } else if args[1] == "dec" {
        let data = BigUint::from_str_radix(&args[3], 16).unwrap();

        let rsa_private_json: Value = serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();

        let private_key: RSAPrivateKey = RSAPrivateKey { 
            d: BigUint::from_str_radix(rsa_private_json["d"].as_str().unwrap(), 16).unwrap(), 
            n: BigUint::from_str_radix(rsa_private_json["n"].as_str().unwrap(), 16).unwrap()
        };

        let decypher = rsa::decrypt(&data, &private_key);
        println!("Decrypted message: {}", std::str::from_utf8(&decypher.to_bytes_be()).unwrap())
    } else {
        print_help();
        return;
    }
}