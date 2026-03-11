#include "polynomial.h"

// ============================================================================
// Polynomial (Plaintext) Implementation
// ============================================================================

ZZ Polynomial::evaluateAt(const ZZ &y, const ZZ &p) const
{
    if (coefficients.empty())
        return ZZ(0);

    // Reduce y modulo p to keep everything small
    ZZ y_red = y % p;
    if (y_red < 0)
        y_red += p;

    ZZ result(0);

    // Horner's rule:
    // P(x) = a0 + a1 x + ... + ad x^d
    // Evaluate as (((ad x + a_{d-1}) x + ...) x + a0) mod p
    for (auto it = coefficients.rbegin(); it != coefficients.rend(); ++it)
    {
        // result = (result * y_red) mod p
        result = NTL::MulMod(result, y_red, p);

        // coeff may be negative; normalize to [0, p-1]
        ZZ c = *it % p;
        if (c < 0)
            c += p;

        // result = (result + c) mod p
        result = NTL::AddMod(result, c, p);
    }

    return result;
}

void Polynomial::addPoly(const Polynomial &other)
{
    // Resize if other polynomial is larger
    if (other.coefficients.size() > coefficients.size())
    {
        coefficients.resize(other.coefficients.size(), NTL::to_ZZ(0));
    }

    // Add coefficients in-place
    for (size_t i = 0; i < other.coefficients.size(); ++i)
    {
        coefficients[i] += other.coefficients[i];
    }
}

void Polynomial::mulPoly(const Polynomial &other)
{
    if (coefficients.empty() || other.coefficients.empty())
    {
        coefficients = {NTL::to_ZZ(0)};
        return;
    }

    std::vector<ZZ> result_coeffs(coefficients.size() + other.coefficients.size() - 1, NTL::to_ZZ(0));

    for (size_t i = 0; i < coefficients.size(); ++i)
    {
        for (size_t j = 0; j < other.coefficients.size(); ++j)
        {
            result_coeffs[i + j] += coefficients[i] * other.coefficients[j];
        }
    }

    coefficients = std::move(result_coeffs);
}

void Polynomial::derivative()
{
    if (coefficients.size() <= 1)
    {
        coefficients = {NTL::to_ZZ(0)};
        return;
    }

    std::vector<ZZ> result_coeffs(coefficients.size() - 1);

    for (size_t i = 1; i < coefficients.size(); ++i)
    {
        result_coeffs[i - 1] = coefficients[i] * NTL::to_ZZ(i);
    }

    coefficients = std::move(result_coeffs);
}

// ============================================================================
// PaillierPolynomial (Encrypted) Implementation
// ============================================================================

Ciphertext PaillierPolynomial::evaluateAt(const ZZ &y) const
{
    // Start with encryption of 0: E(0) = 1 mod n^2
    Ciphertext result = NTL::to_ZZ(1);
    ZZ y_power = NTL::to_ZZ(1); // y^0 initially

    for (size_t i = 0; i < coefficients.size(); ++i)
    {
        // E(coeff_i * y^i) = E(coeff_i)^(y^i) using homomorphic scalar multiplication
        Ciphertext term = ::mul(coefficients[i], y_power, public_key);
        // E(sum) = E(result) * E(term) using homomorphic addition
        result = ::add(result, term, public_key);
        y_power = NTL::MulMod(y_power, y, public_key.n); // Update y^i to y^(i+1)
    }

    return result;
}

void PaillierPolynomial::addPoly(const PaillierPolynomial &other)
{
    // Resize if other polynomial is larger
    if (other.coefficients.size() > coefficients.size())
    {
        coefficients.resize(other.coefficients.size(), NTL::to_ZZ(1)); // E(0) = 1
    }

    // Add coefficients in-place using homomorphic addition
    for (size_t i = 0; i < other.coefficients.size(); ++i)
    {
        coefficients[i] = ::add(coefficients[i], other.coefficients[i], public_key);
    }
}

void PaillierPolynomial::mulPoly(const Polynomial &plaintext_poly)
{
    if (coefficients.empty() || plaintext_poly.coefficients.empty())
    {
        // Set to encryption of zero polynomial
        coefficients = {enc(NTL::to_ZZ(0), public_key)};
        return;
    }

    // Result will have degree = degree(this) + degree(plaintext)
    std::vector<Ciphertext> result_coeffs(coefficients.size() + plaintext_poly.coefficients.size() - 1);

    // Initialize each coefficient as E(0) = 1 mod n^2
    for (auto &coeff : result_coeffs)
        coeff = NTL::to_ZZ(1);

    // Compute polynomial multiplication: E(P1) * P2
    for (size_t i = 0; i < coefficients.size(); ++i)
    {
        for (size_t j = 0; j < plaintext_poly.coefficients.size(); ++j)
        {
            // E(a_i) * b_j = E(a_i * b_j) using homomorphic scalar multiplication
            Ciphertext term = ::mul(coefficients[i], plaintext_poly.coefficients[j], public_key);
            // Add to result[i+j]: E(result[i+j]) = E(result[i+j]) * E(term)
            result_coeffs[i + j] = ::add(result_coeffs[i + j], term, public_key);
        }
    }

    coefficients = std::move(result_coeffs);
}

void PaillierPolynomial::derivative()
{
    if (coefficients.size() <= 1)
    {
        // Derivative of constant is zero
        coefficients = {enc(NTL::to_ZZ(0), public_key)};
        return;
    }

    std::vector<Ciphertext> result_coeffs(coefficients.size() - 1);

    for (size_t i = 0; i < result_coeffs.size(); ++i)
    {
        // E(a_{i+1} * (i+1)) = E(a_{i+1})^(i+1)
        result_coeffs[i] = ::mul(coefficients[i + 1], NTL::to_ZZ(i + 1), public_key);
    }

    coefficients = std::move(result_coeffs);
}

// ============================================================================
// Utility Functions
// ============================================================================

// Encode a set of values as a plaintext polynomial by treating them as roots
// P(x) = (x - r1)(x - r2)...(x - rn) with coefficients reduced modulo n
Polynomial encodeAsPolynomial(const std::vector<ZZ> &roots, const ZZ &n)
{
    if (roots.empty())
    {
        // Empty polynomial, return constant 1
        return Polynomial({NTL::to_ZZ(1)});
    }

    // Start with P(x) = (x - r0) = -r0 + 1*x
    // Normalize to [0, n)
    ZZ c0 = (-roots[0]) % n;
    if (c0 < 0)
        c0 += n;
    std::vector<ZZ> poly = {c0, NTL::to_ZZ(1)};

    // Iteratively multiply by (x - ri) for each root
    for (size_t i = 1; i < roots.size(); ++i)
    {
        // New polynomial will have degree one higher
        std::vector<ZZ> new_poly(poly.size() + 1, NTL::to_ZZ(0));

        // Multiply existing polynomial by (x - roots[i])
        // (a0 + a1*x + ... + an*x^n) * (x - ri)
        // = -ri*a0 + (a0 - ri*a1)*x + (a1 - ri*a2)*x^2 + ... + an*x^(n+1)

        for (size_t j = 0; j < poly.size(); ++j)
        {
            // Contribution from x * aj*x^j = aj*x^(j+1)
            new_poly[j + 1] = (new_poly[j + 1] + poly[j]) % n;
            // Contribution from -ri * aj*x^j = -ri*aj*x^j
            new_poly[j] = (new_poly[j] - (roots[i] * poly[j]) % n) % n;
        }

        // Normalize all coefficients to [0, n)
        for (auto &coeff : new_poly)
        {
            coeff = coeff % n;
            if (coeff < 0)
                coeff += n;
        }

        poly = std::move(new_poly);
    }

    return poly;
}

// Encode a set of values as a Paillier-encrypted polynomial by treating them as roots
// P(x) = (x - r1)(x - r2)...(x - rn), then encrypts all coefficients
PaillierPolynomial encodeAsPaillierPolynomial(const std::vector<ZZ> &roots, const PubKey &pk)
{
    // First, encode as plaintext polynomial with coefficients mod n
    Polynomial plaintext_poly = encodeAsPolynomial(roots, pk.n);

    // Encrypt each coefficient
    std::vector<Ciphertext> encrypted_coeffs;
    encrypted_coeffs.reserve(plaintext_poly.coefficients.size());

    for (const auto &coeff : plaintext_poly.coefficients)
    {
        encrypted_coeffs.push_back(enc(coeff, pk));
    }

    // Return as PaillierPolynomial
    return PaillierPolynomial(encrypted_coeffs, pk);
}

// Encrypt a plaintext polynomial using Paillier encryption
PaillierPolynomial encrypt(const Polynomial &poly, const PubKey &pk)
{
    std::vector<Ciphertext> encrypted_coeffs;
    encrypted_coeffs.reserve(poly.coefficients.size());

    for (const auto &coeff : poly.coefficients)
    {
        encrypted_coeffs.push_back(enc(coeff, pk));
    }

    return PaillierPolynomial(encrypted_coeffs, pk);
}
