#include "shamir.h"

namespace yyh26 {

using osuCrypto::u64;

std::vector<NTL::ZZ_p> ShareSecret(
    NTL::ZZ_p secret, u64 numShares, u64 threshold, NTL::ZZ p)
{
    NTL::ZZ_p::init(p);
    std::vector<NTL::ZZ_p> shares(numShares);
    NTL::ZZ secret_mod_p = NTL::conv<NTL::ZZ>(secret) % p;

    NTL::ZZ_pX poly;
    NTL::SetCoeff(poly, 0, NTL::conv<NTL::ZZ_p>(secret_mod_p));

    for (long i = 1; i < (long)threshold; i++) {
        NTL::ZZ coef;
        NTL::RandomBnd(coef, p);
        NTL::SetCoeff(poly, i, NTL::conv<NTL::ZZ_p>(coef));
    }

    for (long i = 0; i < (long)numShares; i++) {
        shares[i] = NTL::eval(poly, NTL::to_ZZ_p(i + 1));
    }
    return shares;
}

std::vector<NTL::ZZ_p> GenerateUpdateValues(
    u64 numShares, u64 threshold, NTL::ZZ p)
{
    NTL::ZZ_p::init(p);
    std::vector<NTL::ZZ_p> updates(numShares);

    NTL::ZZ_pX poly;
    NTL::SetCoeff(poly, 0, 0);
    for (long j = 1; j < (long)threshold; j++) {
        NTL::ZZ coef;
        NTL::RandomBnd(coef, p);
        NTL::SetCoeff(poly, j, NTL::conv<NTL::ZZ_p>(coef));
    }

    for (long j = 0; j < (long)numShares; j++) {
        updates[j] = NTL::eval(poly, NTL::to_ZZ_p(j + 1));
    }
    return updates;
}

NTL::ZZ lagrange_interpolation(
    const std::vector<std::pair<NTL::ZZ, NTL::ZZ>>& shares, NTL::ZZ mod)
{
    u64 t = shares.size();
    NTL::ZZ secret(0);
    std::vector<NTL::ZZ> inverses(t, NTL::ZZ(1));
    std::vector<NTL::ZZ> neg_xj(t);

    for (u64 j = 0; j < t; ++j) {
        neg_xj[j] = NTL::SubMod(mod, shares[j].first, mod);
    }

    for (u64 i = 0; i < t; ++i) {
        NTL::ZZ denominator(1);
        for (u64 j = 0; j < t; ++j) {
            if (i != j) {
                NTL::ZZ diff = NTL::SubMod(shares[i].first, shares[j].first, mod);
                denominator = NTL::MulMod(denominator, diff, mod);
            }
        }
        inverses[i] = NTL::InvMod(denominator, mod);
    }

    for (u64 i = 0; i < t; ++i) {
        NTL::ZZ li = inverses[i];
        for (u64 j = 0; j < t; ++j) {
            if (i != j) {
                li = NTL::MulMod(li, neg_xj[j], mod);
            }
        }
        secret = NTL::AddMod(secret, NTL::MulMod(shares[i].second, li, mod), mod);
    }
    return secret;
}

} // namespace yyh26
