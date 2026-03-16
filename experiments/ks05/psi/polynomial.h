#ifndef OTMPSI_CRYPTO_POLYNOMIAL_H_
#define OTMPSI_CRYPTO_POLYNOMIAL_H_

#include <vector>
#include "shared/crypto/defines.h"
#include "shared/crypto/paillier.h"

// Plaintext polynomial with ZZ coefficients
struct Polynomial
{
    std::vector<ZZ> coefficients; // Plaintext coefficients [a0, a1, ..., an]

    // Constructor
    Polynomial(const std::vector<ZZ> &coeffs = {}) : coefficients(coeffs) {}

    // Evaluate polynomial at point y
    // Returns P(y) = a0 + a1*y + a2*y^2 + ... + an*y^n
    ZZ evaluateAt(const ZZ &y, const ZZ &p) const;

    // Add another polynomial in-place
    // Modifies this polynomial: this = this + other
    void addPoly(const Polynomial &other);

    // Multiply with another polynomial in-place
    // Modifies this polynomial: this = this * other
    void mulPoly(const Polynomial &other);

    // Compute the derivative in-place
    // Modifies this polynomial: this = this'
    void derivative();

    // Get degree of polynomial
    size_t degree() const { return coefficients.empty() ? 0 : coefficients.size() - 1; }
};

// Polynomial with Paillier-encrypted coefficients
// Supports: ciphertext+ciphertext addition, plaintext×ciphertext multiplication
// Does NOT support: ciphertext×ciphertext multiplication (Paillier limitation)
struct PaillierPolynomial
{
    std::vector<Ciphertext> coefficients; // Paillier-encrypted coefficients [E(a0), E(a1), ..., E(an)]
    PubKey public_key;                    // Public key for homomorphic operations

    // Constructor
    PaillierPolynomial(const std::vector<ZZ> &encrypted_coeffs, const PubKey &pub_key)
        : coefficients(encrypted_coeffs), public_key(pub_key) {}

    // Evaluate the encrypted polynomial at an unencrypted point y
    // Returns E(P(y)) where P(y) = a0 + a1*y + a2*y^2 + ... + an*y^n
    Ciphertext evaluateAt(const ZZ &y) const;

    // Add another encrypted polynomial in-place (coefficient-wise homomorphic addition)
    // Modifies this polynomial: this = this + other
    void addPoly(const PaillierPolynomial &other);

    // Multiply with a plaintext polynomial in-place
    // Modifies this polynomial: this = this * plaintext_poly (where this is encrypted, plaintext_poly is plaintext)
    void mulPoly(const Polynomial &plaintext_poly);

    // Compute the derivative of the encrypted polynomial in-place
    // Modifies this polynomial: this = this'
    void derivative();

    // Get degree of polynomial
    size_t degree() const { return coefficients.empty() ? 0 : coefficients.size() - 1; }
};

// Encode a set of values as a plaintext polynomial by treating them as roots
// Returns polynomial P(x) = (x - r1)(x - r2)...(x - rn) with coefficients mod n
Polynomial encodeAsPolynomial(const std::vector<ZZ> &roots, const ZZ &n);

// Encode a set of values as a Paillier-encrypted polynomial by treating them as roots
// P(x) = (x - r1)(x - r2)...(x - rn), then encrypts all coefficients
// Returns a PaillierPolynomial with all coefficients encrypted
PaillierPolynomial encodeAsPaillierPolynomial(const std::vector<ZZ> &roots, const PubKey &pk);

// Encrypt a plaintext polynomial using Paillier encryption
// Returns a PaillierPolynomial with all coefficients encrypted
PaillierPolynomial encrypt(const Polynomial &poly, const PubKey &pk);

#endif // OTMPSI_CRYPTO_POLYNOMIAL_H_