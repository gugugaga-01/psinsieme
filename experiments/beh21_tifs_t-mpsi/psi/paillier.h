#ifndef PAILLIER_H
#define PAILLIER_H

#include <vector>
#include "Defines.h"

// Type aliases
using Plaintext = ZZ;
using Ciphertext = ZZ;

struct PubKey
{
    ZZ n;     // modulus (n = p * q)
    ZZ n2;    // n^2
    ZZ g;     // generator (g = n + 1)
    ZZ theta; // verification value (theta = m * beta mod n, where m = p' * q')
    ZZ delta; // delta = n! (factorial) for n-of-n threshold
};

struct PrivKey
{
    ZZ s; // secret key share for party i
};

// Single-key Paillier key generation
void keyGen(PubKey &pk, PrivKey &sk, long bits);

// Distributed n-of-n Paillier key generation
void distributedKeyGen(long bits, long n, const ZZ &seed,
                       PubKey &pk,
                       std::vector<PrivKey> &sks);

// Encryption / Decryption
Ciphertext enc(const Plaintext &m, const PubKey &pk);
Plaintext dec(const Ciphertext &c, const PubKey &pk, const PrivKey &sk);

// Partial decrypt (each party computes one share)
Ciphertext partialDec(const Ciphertext &c, const PubKey &pk, const PrivKey &sk);

// Combine all partial decryptions to recover plaintext
Plaintext fuseDec(const std::vector<Ciphertext> &parts,
                  const PubKey &pk);

// Homomorphic operations
Ciphertext add(const Ciphertext &c1, const Ciphertext &c2, const PubKey &pk);
Ciphertext sub(const Ciphertext &c1, const Ciphertext &c2, const PubKey &pk);
Ciphertext mul(const Ciphertext &c, const Plaintext &k, const PubKey &pk);

// Rerandomization
Ciphertext rerand(const Ciphertext &c, const PubKey &pk);

// Utility
ZZ randCoprime(const ZZ &n);

#endif // PAILLIER_H