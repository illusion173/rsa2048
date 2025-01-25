from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_prime(bits=1024):
    """Generates a prime number with the specified number of bits."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    ).private_numbers().p

def generate_rsa_primes():
    """Generates two distinct 1024-bit primes for RSA."""
    p = generate_prime()
    q = generate_prime()

    # Ensure that p and q are distinct
    while p == q:
        print("p and q are the same, generating a new q...")
        q = generate_prime()

    return p, q

if __name__ == "__main__":
    p, q = generate_rsa_primes()

    print("Generated prime p:", p)
    print("Generated prime q:", q)
