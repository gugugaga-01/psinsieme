#include "paillier.h"
#include <stdexcept>

/* --------------------------------------------------
 * Utility
 * -------------------------------------------------- */

ZZ randCoprime(const ZZ &n)
{
    if (n <= 2)
        throw std::invalid_argument("n must be > 2 for randCoprime");

    while (true)
    {
        ZZ r = NTL::RandomBnd(n);
        // Ensure r > 1 to avoid weak randomness (r=0 or r=1)
        if (r > 1 && NTL::GCD(r, n) == 1)
            return r;
    }
}

/* --------------------------------------------------
 * Factorial computation
 * -------------------------------------------------- */

ZZ factorial(long n)
{
    ZZ result(1);
    for (long i = 2; i <= n; ++i)
    {
        result *= i;
    }
    return result;
}

/* --------------------------------------------------
 * L function: L(x) = (x - 1) / n
 * -------------------------------------------------- */

ZZ L_function(const ZZ &x, const ZZ &n)
{
    return (x - 1) / n;
}

/* --------------------------------------------------
 * LCM helper function
 * -------------------------------------------------- */

ZZ lcm(const ZZ &a, const ZZ &b)
{
    // Compute LCM = (a * b) / GCD(a, b)
    // Rewritten as (a / GCD(a, b)) * b to avoid overflow
    return (a / NTL::GCD(a, b)) * b;
}

/* --------------------------------------------------
 * Single key generation
 * -------------------------------------------------- */

void keyGen(PubKey &pk, PrivKey &sk, long bits)
{
    long err = 80;

    ZZ p = NTL::GenPrime_ZZ(bits / 2, err);
    ZZ q = NTL::GenPrime_ZZ(bits / 2, err);
    while (p == q)
        q = NTL::GenPrime_ZZ(bits / 2, err);

    ZZ n = p * q;
    ZZ lambda = lcm(p - 1, q - 1); // Use our lcm function consistently

    pk.n = n;
    pk.n2 = n * n;
    pk.g = n + 1;

    sk.s = lambda;
}

/* --------------------------------------------------
 * Distributed n-of-n threshold Paillier key generation
 * Uses safe primes for enhanced security
 * -------------------------------------------------- */

void distributedKeyGen(long bits, long n, const ZZ &seed,
                       PubKey &pk,
                       std::vector<PrivKey> &sks)
{
    if (n <= 0)
        throw std::invalid_argument("n must be > 0");

    long err = 80;

    NTL::SetSeed(seed);

    // Generate safe primes: p = 2p' + 1, q = 2q' + 1
    ZZ pp, qq;
    pp = NTL::GenGermainPrime_ZZ(bits / 4, err);
    qq = NTL::GenGermainPrime_ZZ(bits / 4, err);
    while (pp == qq)
    {
        qq = NTL::GenGermainPrime_ZZ(bits / 4, err);
    }

    ZZ p = 2 * pp + 1;
    ZZ q = 2 * qq + 1;
    ZZ N = p * q;
    ZZ m = pp * qq; // m = p' * q'

    // Public key setup
    pk.n = N;
    pk.n2 = N * N;
    pk.g = N + 1;
    pk.delta = factorial(n);

    // Generate random beta and compute theta
    NTL::SetSeed(seed);
    ZZ beta = randCoprime(N);
    pk.theta = NTL::MulMod(m, beta, N);

    // Generate polynomial coefficients for secret sharing
    // For n-of-n, we use a polynomial of degree n-1
    std::vector<ZZ> coefficients;
    coefficients.resize(n);
    coefficients[0] = NTL::MulMod(beta, m, N * m); // constant term = beta * m

    for (long i = 1; i < n; ++i)
    {
        coefficients[i] = NTL::RandomBnd(N * m);
    }

    // Generate secret key shares by evaluating polynomial at points 1, 2, ..., n
    sks.clear();
    sks.resize(n);

    for (long i = 0; i < n; ++i)
    {
        ZZ key(0);
        ZZ x_power(1); // x^j where x = i+1

        for (long j = 0; j < n; ++j)
        {
            key = (key + coefficients[j] * x_power) % (N * m);
            x_power = (x_power * (i + 1)) % (N * m);
        }

        sks[i].s = key;
    }
    NTL::SetSeed(NTL::ZZ::zero());
}

/* --------------------------------------------------
 * Encryption
 * -------------------------------------------------- */

Ciphertext enc(const Plaintext &m, const PubKey &pk)
{
    // Validate plaintext range: should be in [0, n)
    Plaintext mm = m % pk.n;
    if (mm < 0)
        mm += pk.n;

    if (mm < 0 || mm >= pk.n)
        throw std::invalid_argument("plaintext out of valid range [0, n)");

    ZZ r = randCoprime(pk.n);

    // Compute c = g^m * r^n mod n^2
    Ciphertext c1 = NTL::PowerMod(pk.g, mm, pk.n2);
    Ciphertext c2 = NTL::PowerMod(r, pk.n, pk.n2);

    return NTL::MulMod(c1, c2, pk.n2);
}

/* --------------------------------------------------
 * Full decryption (single key)
 * -------------------------------------------------- */

Plaintext dec(const Ciphertext &c, const PubKey &pk, const PrivKey &sk)
{
    // Validate ciphertext range
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    // Compute L(c^λ mod n^2) where L(x) = (x-1)/n
    ZZ u = NTL::PowerMod(c, sk.s, pk.n2);
    ZZ L = (u - 1) / pk.n;

    // Compute μ = L(g^λ mod n^2)^{-1} mod n
    ZZ ug = NTL::PowerMod(pk.g, sk.s, pk.n2);
    ZZ Lg = (ug - 1) / pk.n;

    ZZ mu = NTL::InvMod(Lg % pk.n, pk.n);

    // Decrypt: m = L * μ mod n
    Plaintext m = NTL::MulMod(L, mu, pk.n);

    return m;
}

/* --------------------------------------------------
 * Partial decrypt: d_i = c^{2 * delta * s_i} mod n^2
 * -------------------------------------------------- */

Ciphertext partialDec(const Ciphertext &c, const PubKey &pk, const PrivKey &sk)
{
    // Validate ciphertext range
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    // Compute partial decryption: c^(2 * delta * s_i) mod n^2
    ZZ exponent = 2 * pk.delta * sk.s;
    return NTL::PowerMod(c, exponent, pk.n2);
}

/* --------------------------------------------------
 * Fuse partial decryptions (n-of-n threshold)
 * Combines partial decryptions using Lagrange interpolation
 * -------------------------------------------------- */

Plaintext fuseDec(const std::vector<Ciphertext> &parts,
                  const PubKey &pk)
{
    long n = parts.size();
    if (n == 0)
        throw std::invalid_argument("no partial decryptions provided");

    // Compute Lagrange coefficients for n-of-n scheme
    // lambda_i = delta * prod_{j!=i} j / (j - i)
    std::vector<ZZ> lambdas;
    lambdas.resize(n);

    for (long i = 0; i < n; ++i)
    {
        ZZ lambda = pk.delta;

        for (long j = 0; j < n; ++j)
        {
            if (i != j)
            {
                // Parties are numbered 1, 2, ..., n (not 0, 1, ..., n-1)
                long x_i = i + 1;
                long x_j = j + 1;

                lambda *= x_j;
                lambda /= (x_j - x_i);
            }
        }

        lambdas[i] = lambda;
    }

    // Combine partial decryptions: product = Π parts[i]^(2 * lambda_i) mod n^2
    ZZ product(1);
    for (long i = 0; i < n; ++i)
    {
        ZZ exponent = 2 * lambdas[i];
        ZZ term = NTL::PowerMod(parts[i], exponent, pk.n2);
        product = NTL::MulMod(product, term, pk.n2);
    }

    // Apply L function
    ZZ L = L_function(product, pk.n);

    // Compute inverse: (4 * delta^2 * theta)^{-1} mod n
    ZZ inv_temp = 4 * pk.delta * pk.delta % pk.n;
    inv_temp = NTL::MulMod(inv_temp, pk.theta, pk.n);
    inv_temp = NTL::InvMod(inv_temp, pk.n);

    // Decrypt: m = L * inv_temp mod n
    Plaintext m = NTL::MulMod(L, inv_temp, pk.n);

    return m;
}

/* --------------------------------------------------
 * Homomorphic operations
 * -------------------------------------------------- */

Ciphertext add(const Ciphertext &c1, const Ciphertext &c2, const PubKey &pk)
{
    // Validate ciphertext ranges
    if (c1 <= 0 || c1 >= pk.n2 || c2 <= 0 || c2 >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    // Homomorphic addition: E(m1 + m2) = E(m1) * E(m2) mod n^2
    return NTL::MulMod(c1, c2, pk.n2);
}

Ciphertext sub(const Ciphertext &c1, const Ciphertext &c2, const PubKey &pk)
{
    // Validate ciphertext ranges
    if (c1 <= 0 || c1 >= pk.n2 || c2 <= 0 || c2 >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    // Homomorphic subtraction: E(m1 - m2) = E(m1) * E(m2)^{-1} mod n^2
    Ciphertext inv = NTL::InvMod(c2, pk.n2);
    return NTL::MulMod(c1, inv, pk.n2);
}

Ciphertext mul(const Ciphertext &c, const Plaintext &k, const PubKey &pk)
{
    // Validate ciphertext range
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    // Normalize negative scalar to positive representation
    Plaintext kk = (k >= 0 ? k : pk.n + k);

    // Additional validation: ensure normalized scalar is in valid range
    if (kk < 0 || kk >= pk.n)
        throw std::invalid_argument("scalar out of valid range after normalization");

    // Homomorphic scalar multiplication: E(m * k) = E(m)^k mod n^2
    return NTL::PowerMod(c, kk, pk.n2);
}

/* --------------------------------------------------
 * Rerandomization (optimized)
 * -------------------------------------------------- */

Ciphertext rerand(const Ciphertext &c, const PubKey &pk)
{
    // Validate ciphertext range
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    // More efficient rerandomization: multiply by r^n mod n^2
    // This is equivalent to adding encryption of 0, but faster
    ZZ r = randCoprime(pk.n);
    ZZ r_n = NTL::PowerMod(r, pk.n, pk.n2);
    return NTL::MulMod(c, r_n, pk.n2);
}