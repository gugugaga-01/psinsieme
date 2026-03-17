#pragma once

#include <vector>
#include "defines.h"
#include "paillier.h"

namespace mpsi::ks05 {

struct Polynomial {
    std::vector<ZZ> coefficients; // [a0, a1, ..., an]

    Polynomial(const std::vector<ZZ>& coeffs = {}) : coefficients(coeffs) {}

    ZZ evaluateAt(const ZZ& y, const ZZ& p) const;
    void addPoly(const Polynomial& other);
    void mulPoly(const Polynomial& other);
    void derivative();
    size_t degree() const { return coefficients.empty() ? 0 : coefficients.size() - 1; }
};

struct PaillierPolynomial {
    std::vector<Ciphertext> coefficients; // [E(a0), E(a1), ..., E(an)]
    PubKey public_key;

    PaillierPolynomial(const std::vector<ZZ>& encrypted_coeffs, const PubKey& pub_key)
        : coefficients(encrypted_coeffs), public_key(pub_key) {}

    Ciphertext evaluateAt(const ZZ& y) const;
    void addPoly(const PaillierPolynomial& other);
    void mulPoly(const Polynomial& plaintext_poly);
    void derivative();
    size_t degree() const { return coefficients.empty() ? 0 : coefficients.size() - 1; }
};

Polynomial encodeAsPolynomial(const std::vector<ZZ>& roots, const ZZ& n);
PaillierPolynomial encodeAsPaillierPolynomial(const std::vector<ZZ>& roots, const PubKey& pk);
PaillierPolynomial encrypt(const Polynomial& poly, const PubKey& pk);

} // namespace mpsi::ks05
