use num_bigint::{BigUint, ToBigUint, RandBigInt, BigInt};
use num_traits::{self, CheckedSub, CheckedDiv};
use num_integer::Integer;

// Calculate the number of trial divisions that gives the best speed in
// combination with Miller-Rabin prime test, based on the size of the prime.
fn calc_trial_divisions(bits: u64) -> u64 {
    if bits <= 512 {
        return 64;
    }
    else if bits <= 1024 {
        return 128;
    }
    else if bits <= 2048 {
        return 384;
    }
    else if bits <= 4096 {
        return 1024;
    }
    return 2048;
}

// Implimentation of Miller-Rabin probabilistic primality test algorithm
// (Который я успешно спиздил у OpenSSL)
// https://github.com/openssl/openssl/blob/3ee3c4d2abeeeadc8d33498d1466a3a8381d286b/crypto/bn/bn_prime.c#L264
pub fn is_probably_prime(bu: & BigUint, primes: & [BigUint]) -> bool {
    // If number is <= 1 its not prime
    if *bu <= num_traits::One::one() {
        return false;
    }

    // Number must be odd
    if bu.bit(0) {
        // Check for trivial case
        if *bu == 3.to_biguint().unwrap() {
            return true;
        }
    } else {
        // Check for edge-case of the only even prime
        return *bu == 2.to_biguint().unwrap();
    }

    // Check small factors
    for p in primes {
        let bmod = bu.modpow(&num_traits::One::one(), p);
        if bmod == num_traits::zero() {
            return bmod == *p;
        }
    }

    let bu1 = bu.checked_sub(&num_traits::one()).unwrap();

    // Calculate the largest 'a' such that 2^a divides bu-1
    let mut a = 1;
    while !bu1.bit(a) {
        a += 1;
    }

    let m = bu1.clone() >> a;

    // Estimate the number of needed iterations (heuristically)
    let iters = if bu.bits() > 2048 { 128 } else { 64 };

    let mut rng = rand::thread_rng();

    for _ in 0..iters {
        let bur = rng.gen_biguint_range(&2.to_biguint().unwrap(), &bu1);
        
        let mut z = bur.modpow(&m, bu);

        if z == num_traits::one() || z == bu1 {
            continue;
        }

        for _ in 1..a {
            z = z.modpow(&2.to_biguint().unwrap(), bu);

            if z == bu1 {
                break;
            }
            if z == num_traits::one() {
                return false;
            }
        }
    }

    true
}


pub fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) / gcd(a, b)
}

pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();

    while b != num_traits::zero() {
        let t = b.clone();
        b = a.modpow(&num_traits::one(), &b);
        a = t;
    }

    a
}

pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut x0: BigInt = num_traits::one();
    let mut x1: BigInt = num_traits::zero();
    let mut y0: BigInt = num_traits::zero();
    let mut y1: BigInt = num_traits::one();

    let mut a = a.clone();
    let mut b = b.clone();

    while b != num_traits::zero() {
        let (q, r) = a.div_rem(&b);

        a = b;
        b = r;

        let temp_x = x0.clone();
        let temp_y = y0.clone();

        x0 = x1.clone();
        y0 = y1.clone();

        x1 = temp_x - &q * x1;
        y1 = temp_y - &q * y1;
    }

    (a, x0, y0)
}