#include "polynomial.h"

namespace mpsi::ks05 {

ZZ Polynomial::evaluateAt(const ZZ& y, const ZZ& p) const {
    if (coefficients.empty())
        return ZZ(0);

    ZZ y_red = y % p;
    if (y_red < 0)
        y_red += p;

    ZZ result(0);

    for (auto it = coefficients.rbegin(); it != coefficients.rend(); ++it) {
        result = NTL::MulMod(result, y_red, p);

        ZZ c = *it % p;
        if (c < 0)
            c += p;

        result = NTL::AddMod(result, c, p);
    }

    return result;
}

void Polynomial::addPoly(const Polynomial& other) {
    if (other.coefficients.size() > coefficients.size())
        coefficients.resize(other.coefficients.size(), NTL::to_ZZ(0));

    for (size_t i = 0; i < other.coefficients.size(); ++i)
        coefficients[i] += other.coefficients[i];
}

void Polynomial::mulPoly(const Polynomial& other) {
    if (coefficients.empty() || other.coefficients.empty()) {
        coefficients = {NTL::to_ZZ(0)};
        return;
    }

    std::vector<ZZ> result_coeffs(coefficients.size() + other.coefficients.size() - 1, NTL::to_ZZ(0));

    for (size_t i = 0; i < coefficients.size(); ++i)
        for (size_t j = 0; j < other.coefficients.size(); ++j)
            result_coeffs[i + j] += coefficients[i] * other.coefficients[j];

    coefficients = std::move(result_coeffs);
}

void Polynomial::derivative() {
    if (coefficients.size() <= 1) {
        coefficients = {NTL::to_ZZ(0)};
        return;
    }

    std::vector<ZZ> result_coeffs(coefficients.size() - 1);

    for (size_t i = 1; i < coefficients.size(); ++i)
        result_coeffs[i - 1] = coefficients[i] * NTL::to_ZZ(i);

    coefficients = std::move(result_coeffs);
}

// PaillierPolynomial implementation

Ciphertext PaillierPolynomial::evaluateAt(const ZZ& y) const {
    Ciphertext result = NTL::to_ZZ(1);
    ZZ y_power = NTL::to_ZZ(1);

    for (size_t i = 0; i < coefficients.size(); ++i) {
        Ciphertext term = mul(coefficients[i], y_power, public_key);
        result = add(result, term, public_key);
        y_power = NTL::MulMod(y_power, y, public_key.n);
    }

    return result;
}

void PaillierPolynomial::addPoly(const PaillierPolynomial& other) {
    if (other.coefficients.size() > coefficients.size())
        coefficients.resize(other.coefficients.size(), NTL::to_ZZ(1)); // E(0) = 1

    for (size_t i = 0; i < other.coefficients.size(); ++i)
        coefficients[i] = add(coefficients[i], other.coefficients[i], public_key);
}

void PaillierPolynomial::mulPoly(const Polynomial& plaintext_poly) {
    if (coefficients.empty() || plaintext_poly.coefficients.empty()) {
        coefficients = {enc(NTL::to_ZZ(0), public_key)};
        return;
    }

    std::vector<Ciphertext> result_coeffs(coefficients.size() + plaintext_poly.coefficients.size() - 1);

    for (auto& coeff : result_coeffs)
        coeff = NTL::to_ZZ(1);

    for (size_t i = 0; i < coefficients.size(); ++i) {
        for (size_t j = 0; j < plaintext_poly.coefficients.size(); ++j) {
            Ciphertext term = mul(coefficients[i], plaintext_poly.coefficients[j], public_key);
            result_coeffs[i + j] = add(result_coeffs[i + j], term, public_key);
        }
    }

    coefficients = std::move(result_coeffs);
}

void PaillierPolynomial::derivative() {
    if (coefficients.size() <= 1) {
        coefficients = {enc(NTL::to_ZZ(0), public_key)};
        return;
    }

    std::vector<Ciphertext> result_coeffs(coefficients.size() - 1);

    for (size_t i = 0; i < result_coeffs.size(); ++i)
        result_coeffs[i] = mul(coefficients[i + 1], NTL::to_ZZ(i + 1), public_key);

    coefficients = std::move(result_coeffs);
}

// Utility functions

Polynomial encodeAsPolynomial(const std::vector<ZZ>& roots, const ZZ& n) {
    if (roots.empty())
        return Polynomial({NTL::to_ZZ(1)});

    ZZ c0 = (-roots[0]) % n;
    if (c0 < 0)
        c0 += n;
    std::vector<ZZ> poly = {c0, NTL::to_ZZ(1)};

    for (size_t i = 1; i < roots.size(); ++i) {
        std::vector<ZZ> new_poly(poly.size() + 1, NTL::to_ZZ(0));

        for (size_t j = 0; j < poly.size(); ++j) {
            new_poly[j + 1] = (new_poly[j + 1] + poly[j]) % n;
            new_poly[j] = (new_poly[j] - (roots[i] * poly[j]) % n) % n;
        }

        for (auto& coeff : new_poly) {
            coeff = coeff % n;
            if (coeff < 0)
                coeff += n;
        }

        poly = std::move(new_poly);
    }

    return Polynomial(poly);
}

PaillierPolynomial encodeAsPaillierPolynomial(const std::vector<ZZ>& roots, const PubKey& pk) {
    Polynomial plaintext_poly = encodeAsPolynomial(roots, pk.n);

    std::vector<Ciphertext> encrypted_coeffs;
    encrypted_coeffs.reserve(plaintext_poly.coefficients.size());

    for (const auto& coeff : plaintext_poly.coefficients)
        encrypted_coeffs.push_back(enc(coeff, pk));

    return PaillierPolynomial(encrypted_coeffs, pk);
}

PaillierPolynomial encrypt(const Polynomial& poly, const PubKey& pk) {
    std::vector<Ciphertext> encrypted_coeffs;
    encrypted_coeffs.reserve(poly.coefficients.size());

    for (const auto& coeff : poly.coefficients)
        encrypted_coeffs.push_back(enc(coeff, pk));

    return PaillierPolynomial(encrypted_coeffs, pk);
}

} // namespace mpsi::ks05
