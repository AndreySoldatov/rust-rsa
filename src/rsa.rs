use num_bigint::{BigUint, RandBigInt, ToBigUint, ToBigInt};
use num_integer::Integer;
use serde::{Serialize, ser::SerializeStruct};
use num_prime::{self, RandPrime};
use std::{thread, sync::mpsc};

use crate::math_utils;

pub struct RSAKeyPair {
    pub public_key: RSAPublicKey,
    pub private_key: RSAPrivateKey
}

impl Serialize for RSAKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut state = serializer.serialize_struct("RSA", 3)?;
        state.serialize_field("private_key", &self.private_key)?;
        state.serialize_field("public_key", &self.public_key)?;
        state.end()
    }
}

pub struct RSAPublicKey {
    pub e: BigUint,
    pub n: BigUint
}

impl Serialize for RSAPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut state = serializer.serialize_struct("RSA", 3)?;
        state.serialize_field("e", &self.e.to_str_radix(16))?;
        state.serialize_field("n", &self.n.to_str_radix(16))?;
        state.end()
    }
}

pub struct RSAPrivateKey {
    pub d: BigUint,
    pub n: BigUint
}

impl Serialize for RSAPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut state = serializer.serialize_struct("RSA", 3)?;
        state.serialize_field("d", &self.d.to_str_radix(16))?;
        state.serialize_field("n", &self.n.to_str_radix(16))?;
        state.end()
    }
}

impl RSAKeyPair {
    pub fn new(bit_width: u64, workers: u32) -> Self {
        let half_bits = bit_width >> 1;

        let mut rng_local = rand::thread_rng();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();

        for _ in 0..workers {
            let local_tx1 = tx1.clone();
            thread::spawn(move || {
                let mut rng = rand::thread_rng();
                local_tx1.send(rng.gen_prime(half_bits as usize, None)).unwrap();
            });

            let local_tx2 = tx2.clone();
            thread::spawn(move || {
                let mut rng = rand::thread_rng();
                local_tx2.send(rng.gen_prime(half_bits as usize, None)).unwrap();
            });
        }

        let p1: BigUint = rx1.recv().unwrap();
        let p2: BigUint = rx2.recv().unwrap();

        let n = p1.clone() * p2.clone();
        
        let ctf = math_utils::lcm(&(p1 - num_traits::one::<BigUint>()), &(p2 - num_traits::one::<BigUint>()));
        let mut exponent = 65_537.to_biguint().unwrap();
        
        while exponent.gcd(&ctf) != num_traits::one() {
            exponent = rng_local.gen_biguint_range(&3.to_biguint().unwrap(), &65_537.to_biguint().unwrap());
        }

        let ext = exponent.to_bigint().unwrap().extended_gcd(&ctf.to_bigint().unwrap());

        RSAKeyPair {
            public_key: RSAPublicKey { 
                e: exponent,
                n: n.clone()
            }, 
            private_key: RSAPrivateKey { 
                d: (ext.x.mod_floor(&ctf.to_bigint().unwrap()) + ctf.to_bigint().unwrap())
                        .mod_floor(&ctf.to_bigint().unwrap()).to_biguint().unwrap(), 
                n: n.clone()
            } 
        }
    }
}

pub fn encrypt(data: &BigUint, pub_k: &RSAPublicKey) -> BigUint {
    data.modpow(&pub_k.e, &pub_k.n)
}

pub fn decrypt(cypher: &BigUint, priv_k: &RSAPrivateKey) -> BigUint {
    cypher.modpow(&priv_k.d, &priv_k.n)
}