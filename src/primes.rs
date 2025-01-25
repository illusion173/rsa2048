#![allow(clippy::many_single_char_names)]

extern crate num;
extern crate num_bigint as bigint;
extern crate primal;
extern crate rand;
use bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num::{Integer, One, ToPrimitive, Zero};

// Find all prime numbers
fn small_primes(bound: usize) -> Vec<usize> {
    primal::Primes::all().take(bound).collect::<Vec<usize>>()
}

// Modular exponentiation by squaring
pub fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut result = One::one();
    let mut b = base.to_owned();
    let mut exp = exponent.to_owned();

    while exp > Zero::zero() {
        // Accumulate current base if current exponent bit is 1
        if (&exp & 1.to_biguint().unwrap()) == One::one() {
            result *= &b;
            result %= modulus;
        }
        // Get next base by squaring
        b = &b * &b;
        b = &b % modulus;

        // Get next bit of exponent
        exp >>= 1;
    }
    result
}

// Given an even `n`, find first `s` and odd `d` such that n = 2^s*d
fn rewrite(n: &BigUint) -> (BigUint, BigUint) {
    let mut d = n.clone();
    let mut s: BigUint = Zero::zero();
    let one: BigUint = One::one();
    let two = 2.to_biguint().unwrap();

    while d.is_even() {
        d /= &two;
        s += &one;
    }
    (s, d)
}

/// Rabin-Miller primality test
///
/// TODO: this speudocode is outdated. Check for changes in new version.
///
/// [Pseudocode](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
///
///'''text
///     Input: n > 3, an odd integer to be tested for primality;
///     Input: k, a parameter that determines the accuracy of the test
///     Output: composite if n is composite, otherwise probably prime
///     write n − 1 as 2s·d with d odd by factoring powers of 2 from n − 1
///     WitnessLoop: repeat k times:
///       pick a random integer a in the range [2, n − 2]
///        x ← a^d mod n
///        if x = 1 or x = n − 1 then do next WitnessLoop
///       repeat s − 1 times:
///           x ← x2 mod n
///           if x = 1 then return composite
///           if x = n − 1 then do next WitnessLoop
///       return composite
///    return probably prime
///'''

fn rabin_miller(candidate: &BigUint) -> bool {
    // Rabin-Miller until probability of false-positive is < 2^-128
    const K: usize = 128usize;

    //let zero: BigUint = Zero::zero();
    let one: BigUint = One::one();
    let two = 2.to_biguint().unwrap();
    let three = 3.to_biguint().unwrap();

    //println!("prime candidate = {}", candidate.to_bytes_be().to_hex());

    // Rabin-Miller has trouble with even numbers, so special case them
    if candidate == &two {
        return true;
    }
    if candidate == &three {
        return true;
    }
    if candidate.is_even() {
        return false;
    }

    let (mut s, d) = rewrite(&(candidate - &one));
    // Probability of false-positive is 2^-k
    'witness_loop: for _ in 0..K {
        let mut rng = rand::thread_rng();
        let basis = rng.gen_biguint_range(&two, &(candidate - &one));
        let mut x = mod_exp(&basis, &d, candidate);

        if x == one || x == (candidate - &one) {
            continue 'witness_loop;
        }

        while s > one {
            // loop s-1 times

            x = (&x * &x) % candidate;
            if x == one {
                // Composite.
                return false;
            }

            if x == candidate - &one {
                continue 'witness_loop;
            }
            s -= &one;
        }
        // Composite.
        return false;
    }
    // Probably prime.
    true
}

pub fn is_prime(candidate: &BigUint) -> bool {
    for p in small_primes(100).iter() {
        let bigp = p.to_biguint().unwrap();
        if *candidate == bigp {
            return true;
        } else if bigp.divides(candidate) {
            return false;
        }
    }
    rabin_miller(candidate)
}

pub fn big_prime(bitsize: usize) -> BigUint {
    let one: BigUint = One::one();
    let two = 2.to_biguint().unwrap();

    let mut rng = rand::thread_rng();
    let mut candidate = rng.gen_biguint(bitsize.to_u64().unwrap());
    if candidate.is_even() {
        candidate = &candidate + &one;
    }
    while !is_prime(&candidate) {
        candidate = &candidate + &two;
    }
    candidate
}

/// An prime suitable for RSA with exponent `e`
/// The prime `p` - 1 can't be a multiple of `e`
pub fn rsa_prime(size: usize, e: &BigUint) -> BigUint {
    loop {
        let p = big_prime(size);
        if &p % e != One::one() {
            return p;
        }
    }
}

/// Extended Euclidean GCD algorithm
/// Returns k, s,and t such that as + bt = k, where k is the gcd of a and b
///
/// [Pseudocode](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Polynomial_extended_Euclidean_algorithm)
///
///'''text
///     function extended_gcd(a, b)
///     s := 0;    old_s := 1
///     t := 1;    old_t := 0
///     r := b;    old_r := a
///     while r ≠ 0
///        quotient := old_r div r
///         (old_r, r) := (r, old_r - quotient * r)
///         (old_s, s) := (s, old_s - quotient * s)
///        (old_t, t) := (t, old_t - quotient * t)
///     output "Bézout coefficients:", (old_s, old_t)
///     output "greatest common divisor:", old_r
///     output "quotients by the gcd:", (t, s)
///'''

pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    //println!("a={},\tb={}", a, b);

    let (mut s, mut old_s, mut t, mut old_t): (BigInt, BigInt, BigInt, BigInt) =
        (Zero::zero(), One::one(), One::one(), Zero::zero());

    let (mut r, mut old_r) = (b.to_bigint().unwrap(), a.to_bigint().unwrap());

    while r != Zero::zero() {
        let quotient = &old_r / &r;

        let mut tmp = &old_r - &quotient * &r;
        old_r = r;
        r = tmp;

        tmp = &old_s - &quotient * &s;
        old_s = s;
        s = tmp;

        tmp = &old_t - &quotient * &t;
        old_t = t;
        t = tmp;

        //println!("old_r={},\tr={},\told_s={},\ts={},\told_t={},\tt={}",
        //                                old_r,r,old_s,s,old_t,t);
        //println!("gcd= {}, s={}, t={}",&old_r,&s,&t);
    }
    let gcd = old_r;
    (gcd, s, t)
}

/// Returns the multiplicative inverse of a modulo n.
///
/// Bézout's identity asserts that a and n are coprime if and only
/// if there exist integers s and t such that
///    ns+at=1
/// Reducing this identity modulo n gives
///    at=1 \mod n.
///
/// Thus the remainder of the division of t by n, is the multiplicative
/// inverse of a modulo n.
///
/// [Pseudocode](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures)
///
///'''text
/// function inverse(a, n)
///     t := 0;     newt := 1;
///     r := n;     newr := a;
///     while newr ≠ 0
///         quotient := r div newr
///         (t, newt) := (newt, t - quotient * newt)
///        (r, newr) := (newr, r - quotient * newr)
///     if r > 1 then return "a is not invertible"
///     if t < 0 then t := t + n
///    return t
///'''
pub fn invmod(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let (mut t, mut new_t): (BigInt, BigInt) = (Zero::zero(), One::one());

    let (mut r, mut new_r) = (n.to_bigint().unwrap(), a.to_bigint().unwrap());

    while new_r != Zero::zero() {
        let quotient = &r / &new_r;

        let mut tmp = &t - &quotient * &new_t;
        t = new_t;
        new_t = tmp;

        tmp = &r - &quotient * &new_r;
        r = new_r;
        new_r = tmp;
    }
    if r > One::one() {
        return None;
    };
    if t < Zero::zero() {
        t = &t + &n.to_bigint().unwrap()
    };

    Some(t.to_biguint().unwrap())
}
