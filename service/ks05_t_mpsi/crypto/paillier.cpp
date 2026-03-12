#include "paillier.h"
#include <stdexcept>
#include <fstream>

namespace mpsi::ks05 {

ZZ randCoprime(const ZZ& n) {
    if (n <= 2)
        throw std::invalid_argument("n must be > 2 for randCoprime");

    while (true) {
        ZZ r = NTL::RandomBnd(n);
        if (r > 1 && NTL::GCD(r, n) == 1)
            return r;
    }
}

static ZZ factorial(long n) {
    ZZ result(1);
    for (long i = 2; i <= n; ++i)
        result *= i;
    return result;
}

static ZZ L_function(const ZZ& x, const ZZ& n) {
    return (x - 1) / n;
}

static ZZ lcm(const ZZ& a, const ZZ& b) {
    return (a / NTL::GCD(a, b)) * b;
}

void keyGen(PubKey& pk, PrivKey& sk, long bits) {
    long err = 80;

    ZZ p = NTL::GenPrime_ZZ(bits / 2, err);
    ZZ q = NTL::GenPrime_ZZ(bits / 2, err);
    while (p == q)
        q = NTL::GenPrime_ZZ(bits / 2, err);

    ZZ n = p * q;
    ZZ lambda = lcm(p - 1, q - 1);

    pk.n = n;
    pk.n2 = n * n;
    pk.g = n + 1;

    sk.s = lambda;
}

void distributedKeyGen(long bits, long n,
                       PubKey& pk,
                       std::vector<PrivKey>& sks) {
    if (n <= 0)
        throw std::invalid_argument("n must be > 0");

    // IMPORTANT: The caller is responsible for seeding NTL's PRNG
    // (e.g. from /dev/urandom) BEFORE calling this function.
    // This function uses NTL's PRNG as-is for all random operations.

    long err = 80;

    ZZ pp = NTL::GenGermainPrime_ZZ(bits / 4, err);
    ZZ qq = NTL::GenGermainPrime_ZZ(bits / 4, err);
    while (pp == qq)
        qq = NTL::GenGermainPrime_ZZ(bits / 4, err);

    ZZ p = 2 * pp + 1;
    ZZ q = 2 * qq + 1;
    ZZ N = p * q;
    ZZ m = pp * qq;

    pk.n = N;
    pk.n2 = N * N;
    pk.g = N + 1;
    pk.delta = factorial(n);

    ZZ beta = randCoprime(N);
    pk.theta = NTL::MulMod(m, beta, N);

    std::vector<ZZ> coefficients(n);
    coefficients[0] = NTL::MulMod(beta, m, N * m);

    for (long i = 1; i < n; ++i)
        coefficients[i] = NTL::RandomBnd(N * m);

    sks.clear();
    sks.resize(n);

    for (long i = 0; i < n; ++i) {
        ZZ key(0);
        ZZ x_power(1);

        for (long j = 0; j < n; ++j) {
            key = (key + coefficients[j] * x_power) % (N * m);
            x_power = (x_power * (i + 1)) % (N * m);
        }

        sks[i].s = key;
    }

    // Securely wipe the factorization and polynomial coefficients.
    // After this, only the shares in sks[] remain; the caller should
    // distribute them and wipe the ones it doesn't own.
    NTL::clear(p);
    NTL::clear(q);
    NTL::clear(pp);
    NTL::clear(qq);
    NTL::clear(m);
    NTL::clear(beta);
    for (auto& c : coefficients)
        NTL::clear(c);

    // Reseed NTL's PRNG with OS entropy so that all subsequent random
    // operations (encryption randomness, blinding polynomials, etc.)
    // are cryptographically unpredictable and independent per party.
    {
        unsigned char entropy[32];
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (!urandom.good())
            throw std::runtime_error("Cannot open /dev/urandom for reseeding");
        urandom.read(reinterpret_cast<char*>(entropy), sizeof(entropy));
        NTL::SetSeed(NTL::ZZFromBytes(entropy, sizeof(entropy)));
    }
}

Ciphertext enc(const Plaintext& m, const PubKey& pk) {
    Plaintext mm = m % pk.n;
    if (mm < 0)
        mm += pk.n;

    if (mm < 0 || mm >= pk.n)
        throw std::invalid_argument("plaintext out of valid range [0, n)");

    ZZ r = randCoprime(pk.n);

    Ciphertext c1 = NTL::PowerMod(pk.g, mm, pk.n2);
    Ciphertext c2 = NTL::PowerMod(r, pk.n, pk.n2);

    return NTL::MulMod(c1, c2, pk.n2);
}

Plaintext dec(const Ciphertext& c, const PubKey& pk, const PrivKey& sk) {
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    ZZ u = NTL::PowerMod(c, sk.s, pk.n2);
    ZZ L = (u - 1) / pk.n;

    ZZ ug = NTL::PowerMod(pk.g, sk.s, pk.n2);
    ZZ Lg = (ug - 1) / pk.n;

    ZZ mu = NTL::InvMod(Lg % pk.n, pk.n);

    return NTL::MulMod(L, mu, pk.n);
}

Ciphertext partialDec(const Ciphertext& c, const PubKey& pk, const PrivKey& sk) {
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    ZZ exponent = 2 * pk.delta * sk.s;
    return NTL::PowerMod(c, exponent, pk.n2);
}

Plaintext fuseDec(const std::vector<Ciphertext>& parts, const PubKey& pk) {
    long n = parts.size();
    if (n == 0)
        throw std::invalid_argument("no partial decryptions provided");

    std::vector<ZZ> lambdas(n);

    for (long i = 0; i < n; ++i) {
        ZZ lambda = pk.delta;

        for (long j = 0; j < n; ++j) {
            if (i != j) {
                long x_i = i + 1;
                long x_j = j + 1;
                lambda *= x_j;
                lambda /= (x_j - x_i);
            }
        }

        lambdas[i] = lambda;
    }

    ZZ product(1);
    for (long i = 0; i < n; ++i) {
        ZZ exponent = 2 * lambdas[i];
        ZZ term = NTL::PowerMod(parts[i], exponent, pk.n2);
        product = NTL::MulMod(product, term, pk.n2);
    }

    ZZ L = L_function(product, pk.n);

    ZZ inv_temp = 4 * pk.delta * pk.delta % pk.n;
    inv_temp = NTL::MulMod(inv_temp, pk.theta, pk.n);
    inv_temp = NTL::InvMod(inv_temp, pk.n);

    return NTL::MulMod(L, inv_temp, pk.n);
}

Ciphertext add(const Ciphertext& c1, const Ciphertext& c2, const PubKey& pk) {
    if (c1 <= 0 || c1 >= pk.n2 || c2 <= 0 || c2 >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    return NTL::MulMod(c1, c2, pk.n2);
}

Ciphertext sub(const Ciphertext& c1, const Ciphertext& c2, const PubKey& pk) {
    if (c1 <= 0 || c1 >= pk.n2 || c2 <= 0 || c2 >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    Ciphertext inv = NTL::InvMod(c2, pk.n2);
    return NTL::MulMod(c1, inv, pk.n2);
}

Ciphertext mul(const Ciphertext& c, const Plaintext& k, const PubKey& pk) {
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    Plaintext kk = (k >= 0 ? k : pk.n + k);

    if (kk < 0 || kk >= pk.n)
        throw std::invalid_argument("scalar out of valid range after normalization");

    return NTL::PowerMod(c, kk, pk.n2);
}

Ciphertext rerand(const Ciphertext& c, const PubKey& pk) {
    if (c <= 0 || c >= pk.n2)
        throw std::invalid_argument("ciphertext out of valid range (0, n^2)");

    ZZ r = randCoprime(pk.n);
    ZZ r_n = NTL::PowerMod(r, pk.n, pk.n2);
    return NTL::MulMod(c, r_n, pk.n2);
}

} // namespace mpsi::ks05
