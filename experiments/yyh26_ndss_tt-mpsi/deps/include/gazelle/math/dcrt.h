/*
    Fundamental operations for RNS scaling

    Author: Leo de Castro (ldec@mit.edu)
    Date: 03/14/2019
*/

#ifndef LBCRYPTO_MATH_DCRT_H
#define LBCRYPTO_MATH_DCRT_H

#include "poly.h"

namespace lbcrypto {

    inline ubi getBigQ(ui32 endLimb, ui32 startLimb = 0) {
        ubi q = 1;
        for (ui32 i = startLimb; i < endLimb; i++)
            q = q * ubi(params<ui64>::P[i]);
        return q;
    };

    template <typename RingType>
    inline std::pair<uvbi, uv64> compute_qi_star_and_tilde(ui32 endLimb, ui32 startLimb = 0) {
        // typedef ui64 T;
        ui32 numLimbs = endLimb - startLimb;
        uvbi qi_star(numLimbs, 1);
        uv64 qi_tilde(numLimbs, 1);
        for (ui32 i = startLimb; i < endLimb; i++) {
            for (ui32 j = startLimb; j < endLimb; j++) {
                if (j != i) {
                    qi_star[i-startLimb] = qi_star[i-startLimb] * ubi(RingType::getModulus(j));
                    qi_tilde[i-startLimb] = mod_mul_slow(qi_tilde[i-startLimb], mod_inv(RingType::getModulus(j) % RingType::getModulus(i), RingType::getModulus(i)), RingType::getModulus(i));
                }
            }
            assert((qi_star[i-startLimb] * ubi(qi_tilde[i-startLimb])) % ubi(RingType::getModulus(i)) == ubi(1));
        }

        return std::make_pair(qi_star, qi_tilde);
    };

    template <typename RingType, ui32 numLimbs>
    uvbi reconstructDCRTPoly(const DCRTPoly<RingType, numLimbs>& poly, ubi modulus = getBigQ(numLimbs), const bool reduce = true) {
        constexpr ui32 phim = RingType::phim;
        // uvbi result(phim, 0);
        uvbi result(phim);

        auto qi_pair = compute_qi_star_and_tilde<RingType>(numLimbs);
        uvbi qi_star = std::get<0>(qi_pair);
        uv64 qi_tilde = std::get<1>(qi_pair);

        for (ui32 i = 0; i < phim; i++)
            for (ui32 j = 0; j < numLimbs; j++)
                result[i] += ((ubi(poly[j][i]) * ubi(qi_tilde[j])) % ubi(RingType::getModulus(j))) * qi_star[j];

        if (reduce) {
            for (ui32 i = 0; i < phim; i++)
                result[i] %= modulus;
        }

        return result;
    }

    template <typename RingType, ui32 numLimbs>
    uvbi reconstructDCRTPoly(
        const DCRTPoly<RingType, numLimbs>& poly, 
        const pair<uvbi, uv64> qi_pair,
        ubi modulus = getBigQ(numLimbs), 
        const bool reduce = true
    ) {
        constexpr ui32 phim = RingType::phim;
        // uvbi result(phim, 0);
        uvbi result(phim);

        // auto qi_pair = compute_qi_star_and_tilde<RingType>(numLimbs);
        uvbi qi_star = std::get<0>(qi_pair);
        uv64 qi_tilde = std::get<1>(qi_pair);

        for (ui32 i = 0; i < phim; i++)
            for (ui32 j = 0; j < numLimbs; j++)
                result[i] += ((ubi(poly[j][i]) * ubi(qi_tilde[j])) % ubi(RingType::getModulus(j))) * qi_star[j];

        if (reduce) {
            for (ui32 i = 0; i < phim; i++)
                result[i] %= modulus;
        }

        return result;
    }

    template <typename RingType>
    uvbi reconstructDCRTPoly(const Matrix<typename RingType::value_type>& poly, ui32 startLimb, ui32 endLimb, ubi modulus = 0, const bool reduce = true) {
        assert(startLimb < endLimb);
        if (modulus == 0) modulus = getBigQ(endLimb, startLimb);
        ui32 numLimbs = endLimb - startLimb;
        const ui32 phim = poly.innerSize;
        // uvbi result(phim, 0);
        uvbi result(phim);

        auto qi_pair = compute_qi_star_and_tilde<RingType>(endLimb, startLimb);
        uvbi qi_star = std::get<0>(qi_pair);
        uv64 qi_tilde = std::get<1>(qi_pair);

        for (ui32 i = 0; i < phim; i++)
            for (ui32 j = 0; j < numLimbs; j++)
                result[i] += ((ubi(poly[j][i]) * ubi(qi_tilde[j])) % ubi(RingType::getModulus(j+startLimb))) * qi_star[j];


        if (reduce) {
            for (ui32 i = 0; i < phim; i++)
                result[i] %= modulus;
        }

        return result;
    }


    template<typename IntRingType_in, size_t numLimbs_in, size_t numExtLimbs_in, ui64 t>
    class DCRT_Params {
    public:
        typedef IntRingType_in IntRingType;

        using value_type = typename IntRingType::value_type;
        using greater_value_type = typename IntRingType::greater_value_type;
        typedef fl64 float_type;

        static constexpr ui32 numLimbs = numLimbs_in;
        static constexpr ui32 numExtLimbs = numExtLimbs_in;

        static constexpr value_type plaintextModulus = t;

        static constexpr ui64 FLOAT_SCALE = ((ui64)1)<<50;

        // Basis Extension
        value_type qi_tilde[2*numLimbs] __attribute__((aligned(32)));
        value_type * qi_tilde_Shoup = qi_tilde + numLimbs;

        value_type qi_star[numExtLimbs][2*numLimbs] __attribute__((aligned(32)));
        value_type * qi_star_Shoup[numExtLimbs]; //  = qi_star + numLimbs;

        value_type q_p[2*numExtLimbs] __attribute__((aligned(32)));
        value_type * q_p_Shoup = q_p + numExtLimbs;

        // Reverse Basis Extension
        value_type qi_tilde_prime[2*numExtLimbs] __attribute__((aligned(32)));
        value_type * qi_tilde_prime_Shoup = qi_tilde_prime + numExtLimbs;

        value_type qi_star_prime[numLimbs][2*numExtLimbs] __attribute__((aligned(32)));
        value_type * qi_star_prime_Shoup[numLimbs]; //  = qi_star + numLimbs;

        value_type q_p_prime[2*numLimbs] __attribute__((aligned(32)));
        value_type * q_p_prime_Shoup = q_p_prime + numLimbs;


        // Decryption Scaling
        value_type decryptScaleConsts[numLimbs] __attribute__((aligned(32)));
        float_type decryptScaleFloats[numLimbs] __attribute__((aligned(32)));

        // Multiplication Scaling
        value_type multScaleExtender[numExtLimbs] __attribute__((aligned(32)));
        value_type multScaleConsts[numExtLimbs][numLimbs] __attribute__((aligned(32)));
        value_type multScaleFloatInts[numExtLimbs][numLimbs] __attribute__((aligned(32)));
        float_type multScaleFloatsLow[numExtLimbs][numLimbs] __attribute__((aligned(32)));

        // NOTE: below here is CKKS only
        // TODO: should probably subclass these...

        // Modulus Rescaling
        value_type inversesModqi[numLimbs][numLimbs] __attribute__((aligned(32)));  // [modInd][invInd]
        value_type inversesModqi_shoup[numLimbs][numLimbs] __attribute__((aligned(32)));

        // Extended modulus rescaling
        // value_type PinverseModqi[numLimbs] __attribute__((aligned(32)));
        // value_type PinverseModqi_shoup[numLimbs] __attribute__((aligned(32)));

        static constexpr inline value_type compute_shoup(const value_type in, const value_type modulus) {
            return ((greater_value_type)in << IntRingType::getModulusRepresentationBitSize()) / modulus;
        };

        DCRT_Params() {
            CHECK_DEBUG;
            /** Basis Extension **/
            {
                std::fill(std::begin(qi_tilde), std::end(qi_tilde), 0);

                for (ui32 i = 0; i < numExtLimbs; i++) {
                    std::fill(std::begin(qi_star[i]), std::end(qi_star[i]), 0);
                    qi_star_Shoup[i] = qi_star[i] + numLimbs;
                }

                // if (numExtLimbs > 0) std::fill(std::begin(q_p), std::end(q_p), 0);

                // qi_tilde
                for (ui32 i = 0; i < numLimbs; i++) {
                    // Compute qi_star mod qi
                    // Product of other qj
                    value_type qi_star_qi = 1;
                    for (ui32 j = 0; j < numLimbs; j++) {
                        if (j != i)
                            qi_star_qi = mod_mul_slow(qi_star_qi, IntRingType::getModulus(j), IntRingType::getModulus(i));
                    }
                    qi_tilde[i] = mod_inv(qi_star_qi, IntRingType::getModulus(i));
                    qi_tilde_Shoup[i] = ((greater_value_type)qi_tilde[i] << IntRingType::getModulusRepresentationBitSize()) / IntRingType::getModulus(i);
                }
                // qi_star
                for (ui32 j = 0; j < numExtLimbs; j++) {
                    ui32 pjModInd = j + numLimbs; // extInds[j];
                    // Compute qi_star mod pj
                    for (ui32 i = 0; i < numLimbs; i++) {
                        value_type qi_star_pj = 1;
                        for (ui32 k = 0; k < numLimbs; k++) {
                            if (i != k)
                                qi_star_pj = mod_mul_slow(qi_star_pj, IntRingType::getModulus(k), IntRingType::getModulus(pjModInd));
                        }
                        qi_star[j][i] = qi_star_pj;
                        qi_star_Shoup[j][i] = ((greater_value_type)qi_star_pj << IntRingType::getModulusRepresentationBitSize()) / IntRingType::getModulus(pjModInd);
                    }
                }
                // q_p
                for (ui32 j = 0; j < numExtLimbs; j++) {
                    ui32 pjModInd = j + numLimbs;
                    // Compute q mod pj
                    value_type q_pj = 1;
                    for (ui32 i = 0; i < numLimbs; i++) {
                        q_pj = mod_mul_slow(q_pj, IntRingType::getModulus(i), IntRingType::getModulus(pjModInd));
                    }
                    q_p[j] = q_pj;
                    ASSERT_DEBUG(q_pj < IntRingType::getModulus(pjModInd));
                    q_p_Shoup[j] = ((greater_value_type)q_pj << IntRingType::getModulusRepresentationBitSize()) / IntRingType::getModulus(pjModInd);
                }
            }  // Finished basis extension precomputations

            /** Reverse Basis Extension **/
            {
                // std::fill(std::begin(qi_tilde_prime), std::end(qi_tilde_prime), 0);
                for (ui32 i = 0; i < 2*numExtLimbs; i++) qi_tilde_prime[i] = 0;

                for (ui32 i = 0; i < numLimbs; i++) {
                    for (ui32 j = 0; j < 2*numExtLimbs; j++) qi_star_prime[i][j] = 0;
                    // std::fill(std::begin(qi_star_prime[i]), std::end(qi_star_prime[i]), 0);
                    qi_star_prime_Shoup[i] = qi_star_prime[i] + numExtLimbs;
                }

                // if (numExtLimbs > 0) std::fill(std::begin(q_p), std::end(q_p), 0);

                // qi_tilde
                for (ui32 i = 0; i < numExtLimbs; i++) {
                    // Compute qi_star mod qi
                    // Product of other qj
                    value_type qi_star_qi = 1;
                    for (ui32 j = 0; j < numExtLimbs; j++) {
                        if (j != i)
                            qi_star_qi = mod_mul_slow(qi_star_qi, IntRingType::getModulus(j+numLimbs), IntRingType::getModulus(i+numLimbs));
                    }
                    qi_tilde_prime[i] = mod_inv(qi_star_qi, IntRingType::getModulus(i+numLimbs));
                    qi_tilde_prime_Shoup[i] = ((greater_value_type)qi_tilde_prime[i] << IntRingType::getModulusRepresentationBitSize()) / IntRingType::getModulus(i+numLimbs);
                    ASSERT_DEBUG(qi_tilde_prime[i] < IntRingType::getModulus(i+numLimbs));
                }
                // qi_star
                for (ui32 j = 0; j < numLimbs; j++) {
                    // ui32 pjModInd = j + numExtLimbs; // extInds[j];
                    // Compute qi_star mod pj
                    for (ui32 i = 0; i < numExtLimbs; i++) {
                        value_type qi_star_pj = 1;
                        for (ui32 k = 0; k < numExtLimbs; k++) {
                            if (i != k)
                                qi_star_pj = mod_mul_slow(qi_star_pj, IntRingType::getModulus(k+numLimbs), IntRingType::getModulus(j));
                        }
                        qi_star_prime[j][i] = qi_star_pj;
                        qi_star_prime_Shoup[j][i] = ((greater_value_type)qi_star_pj << IntRingType::getModulusRepresentationBitSize()) / IntRingType::getModulus(j);
                    }
                }
                // q_p
                for (ui32 j = 0; j < numLimbs; j++) {
                    // ui32 pjModInd = j + numLimbs;
                    // Compute q mod pj
                    value_type q_pj = 1;
                    for (ui32 i = 0; i < numExtLimbs; i++) {
                        q_pj = mod_mul_slow(q_pj, IntRingType::getModulus(i+numLimbs), IntRingType::getModulus(j));
                    }
                    q_p_prime[j] = q_pj;
                    ASSERT_DEBUG(q_pj < IntRingType::getModulus(j));
                    q_p_prime_Shoup[j] = ((greater_value_type)q_pj << IntRingType::getModulusRepresentationBitSize()) / IntRingType::getModulus(j);
                }
            }  // Finished reverse basis extension precomputations


            /** Decryption Scaling **/
            {
                // qi_tilde
                for (ui32 i = 0; i < numLimbs; i++) {
                    // Compute qi_star mod qi
                    // Product of other qj
                    value_type qi_star_qi = 1;
                    for (ui32 j = 0; j < numLimbs; j++) {
                        if (j != i)
                            qi_star_qi = mod_mul_slow(qi_star_qi, IntRingType::getModulus(j), IntRingType::getModulus(i));
                    }
                    value_type qi_tilde = mod_inv(qi_star_qi, IntRingType::getModulus(i));

                    ubi quot = (ubi(qi_tilde) * ubi(t))/ubi(IntRingType::getModulus(i));
                    decryptScaleConsts[i] = (quot % ubi(t)).toUnsignedLong();

                    ui64 numerator = ((ubi(qi_tilde) * ubi(t)) % ubi(IntRingType::getModulus(i))).toUnsignedLong();
                    decryptScaleFloats[i] = (float_type)numerator/(float_type)IntRingType::getModulus(i);
                }
            }  // Finished decryption scaling precomputation

            /** Multiplication Scaling **/
            {
                auto Qi_star_and_tilde = compute_qi_star_and_tilde<IntRingType>(numLimbs+numExtLimbs);
                uvbi Qi_star = std::get<0>(Qi_star_and_tilde);
                uv64 Qi_tilde = std::get<1>(Qi_star_and_tilde);

                uvbi pj_star(numExtLimbs);
                ubi p = getBigQ(numExtLimbs+numLimbs, numLimbs);
                for (ui32 j = 0; j < numExtLimbs; j++) {
                    ui32 modInd = j + numLimbs;
                    pj_star[j] = p/IntRingType::getModulus(modInd);
                }

                for (ui32 j = 0; j < numExtLimbs; j++) {
                    ui32 modInd = j + numLimbs;
                    multScaleExtender[j] = (
                            ( ubi(plaintextModulus) * ubi(Qi_tilde[modInd]) * pj_star[j] ) % ubi(IntRingType::getModulus(modInd))
                        ).toUnsignedLong();

                    for (ui32 i = 0; i < numLimbs; i++) {
                        ubi bigNumerator = ubi(plaintextModulus) * ubi(Qi_tilde[i]) * p;

                        multScaleConsts[j][i] = (
                                (bigNumerator/IntRingType::getModulus(i)) % ubi(IntRingType::getModulus(modInd))
                            ).toUnsignedLong();


                        ubi smallNumerator = bigNumerator % ubi(IntRingType::getModulus(i));

                        multScaleFloatInts[j][i] = (
                                ubi(FLOAT_SCALE)*smallNumerator / ubi(IntRingType::getModulus(i))
                            ).toUnsignedLong();

                        constexpr ui64 sigBits = 1<<30;
                        multScaleFloatsLow[j][i] = ( (float_type)
                                (( ubi(FLOAT_SCALE)*smallNumerator*ubi(sigBits) / ubi(IntRingType::getModulus(i)) )
                                - ( ubi(sigBits) * multScaleFloatInts[j][i] )
                            ).toUnsignedLong()
                        )/(float_type) sigBits;

                        multScaleFloatsLow[j][i] = trunc(multScaleFloatsLow[j][i] * pow(10, 6))/(float_type)pow(10, 6);
                    }
                }  
            }  // Finished multiplication precomputation


            // NOTE: below here is CKKS only
            // TODO: should probably subclass these...

            /** Modulus Rescaling **/
            {
                for (ui32 modInd = 0; modInd < numLimbs-1; modInd++) 
                    for (ui32 invInd = modInd+1; invInd < numLimbs; invInd++) {
                        inversesModqi[modInd][invInd] = mod_inv(
                            IntRingType::getModulus(invInd),
                            IntRingType::getModulus(modInd)
                        );
                        inversesModqi_shoup[modInd][invInd] = compute_shoup(
                            inversesModqi[modInd][invInd], IntRingType::getModulus(modInd)
                        );

                        assert(
                            mod_mul_slow(
                                IntRingType::getModulus(invInd), inversesModqi[modInd][invInd],
                                IntRingType::getModulus(modInd)
                            ) == 1);
                    }
            }  // Finished modulus rescaling precomputation

            /** Modulus rescaling by extension **/
            // {
            //     // Compute P
            //     ubi P = 1;
            //     for (ui32 i = numLimbs; i < numLimbs+numExtLimbs; i++)
            //         P *= ubi(IntRingType::getModulus(i));

            //     for (ui32 i = 0; i < numLimbs; i++) {
            //         value_type p_mod = (P % ubi(IntRingType::getModulus(i))).toUnsignedLong();
            //         value_type p_inv = mod_inv(p_mod, IntRingType::getModulus(i));
            //         PinverseModqi[i] = p_inv;
            //         PinverseModqi_shoup[i] = compute_shoup(p_inv, IntRingType::getModulus(i));
            //     }
            // }  // Finished modulus extension rescaling precomputation
        };

        template <typename RingType>
        inline void extendBasis(DCRTPoly<RingType, numLimbs + numExtLimbs>& dcrt_poly) const 
        /*
        Extends the DCRT basis from numLimbs to numLimbs + numExtLimbs
        */
        {
            constexpr ui32 phim = RingType::phim;
            // value_type yi[phim][numLimbs];
            auto yi = std::shared_ptr<value_type[phim][numLimbs]>(new value_type[phim][numLimbs]);
            for (ui32 i = 0; i < phim; i++)
                for (ui32 j = 0; j < numLimbs; j++)
                    yi[i][j] = IntRingType::mod_mul_shoup(dcrt_poly[j][i], qi_tilde[j], qi_tilde_Shoup[j], IntRingType::getModulus(j));

            std::shared_ptr<fl64[phim][numLimbs]> zi = std::shared_ptr<fl64[phim][numLimbs]>(new fl64[phim][numLimbs]);
            constexpr ui32 DELTA = 32;
            for (ui32 i = 0; i < phim; i++)
                for (ui32 j = 0; j < numLimbs; j++)
                    zi[i][j] = (fl64)(((greater_value_type)yi[i][j] << DELTA)/IntRingType::getModulus(j));

            auto v_float = std::shared_ptr<fl64[phim]>(new fl64[phim]);
            // std::fill(std::begin(v_float), std::end(v_float), 0);
            for (ui32 i = 0; i < phim; i++) {
                v_float[i] = 0;
                for (ui32 j = 0; j < numLimbs; j++)
                    v_float[i] += zi[i][j];
            }

            auto v = std::shared_ptr<value_type[phim]>(new value_type[phim]);
            for (ui32 i = 0; i < phim; i++) {
                v[i] = std::round(v_float[i]);
                v[i] >>= DELTA;
            }

            for (ui32 pInd = numLimbs; pInd < numExtLimbs+numLimbs; pInd++) {
                for (ui32 k = 0; k < phim; k++) {
                    dcrt_poly.vals[pInd][k] = 0;
                    for (ui32 qInd = 0; qInd < numLimbs; qInd++) {
                        dcrt_poly.vals[pInd][k] = IntRingType::mod(dcrt_poly.vals[pInd][k] +
                                IntRingType::mod_mul_shoup(yi[k][qInd], qi_star[pInd-numLimbs][qInd], qi_star_Shoup[pInd-numLimbs][qInd], IntRingType::getModulus(pInd)),
                            pInd);
                    }
                    dcrt_poly.vals[pInd][k] += IntRingType::getModulus(pInd);

                    dcrt_poly.vals[pInd][k] -= IntRingType::mod_mul_shoup(v[k], q_p[pInd-numLimbs], q_p_Shoup[pInd-numLimbs], IntRingType::getModulus(pInd));

                    dcrt_poly.vals[pInd][k] = IntRingType::mod(dcrt_poly.vals[pInd][k], pInd);
                    // dcrt_poly.vals[pInd][k] = mod(dcrt_poly.vals[pInd][k], pInd);
                }
            }
        }

        template <typename RingType>
        inline void reverseExtendBasis(const Matrix<value_type>& input, DCRTPoly<RingType, numLimbs + numExtLimbs>& result) const 
        /*
        Extends DCRT Basis in the "reverse direction"
        Takes in a Matrix representing limbs for primes p_1 to p_m
        Returns DCRT poly with limbs from (q_1, ... , q_n, p_1, ... , p_m)
        */
        {
            constexpr ui32 phim = RingType::phim;
            ASSERT_DEBUG(input.size() == numExtLimbs);
            ASSERT_DEBUG(input.innerSize == phim);
            auto yi = std::shared_ptr<value_type[phim][numExtLimbs]>(new value_type[phim][numExtLimbs]);
            for (ui32 i = 0; i < phim; i++)
                for (ui32 j = 0; j < numExtLimbs; j++) {
                    yi[i][j] = IntRingType::mod_mul_shoup(input[j][i], qi_tilde_prime[j], qi_tilde_prime_Shoup[j], IntRingType::getModulus(j+numLimbs));
                }

            auto v = std::shared_ptr<value_type[phim]>(new value_type[phim]);
            constexpr ui32 DELTA = 32;
            constexpr ui64 DELTA_SCALE = ((ui64)1) << DELTA;
            for (ui32 i = 0; i < phim; i++) {
                v[i] = 0;
                fl64 v_float = 0;
                for (ui32 j = 0; j < numExtLimbs; j++) {
                    ui32 modInd = j + numLimbs;
                    fl64 toScaleDown = (
                        ((fl64)IntRingType::mod_mul(input[j][i], qi_tilde_prime[j], modInd)) * DELTA_SCALE
                    )/(fl64)IntRingType::getModulus(j);
                    v_float += toScaleDown;
                }
                v[i] = (value_type)round((v_float / ((fl64)DELTA_SCALE)));
            }

            for (ui32 i = 0; i < numExtLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    result.vals[i+numLimbs][j] = input[i][j];

            for (ui32 pInd = 0; pInd < numLimbs; pInd++) {
                for (ui32 k = 0; k < phim; k++) {
                    result.vals[pInd][k] = 0;
                    for (ui32 qInd = 0; qInd < numExtLimbs; qInd++) {
                        result.vals[pInd][k] = IntRingType::mod(result.vals[pInd][k] +
                                IntRingType::mod_mul_shoup(yi[k][qInd], qi_star_prime[pInd][qInd], qi_star_prime_Shoup[pInd][qInd], IntRingType::getModulus(pInd)),
                            pInd);
                    }
                    result.vals[pInd][k] += IntRingType::getModulus(pInd);

                    result.vals[pInd][k] -= IntRingType::mod_mul_shoup(v[k], q_p_prime[pInd], q_p_prime_Shoup[pInd], IntRingType::getModulus(pInd));

                    result.vals[pInd][k] = IntRingType::mod(result.vals[pInd][k], pInd);
                }
            }
        }

        template <typename RingType, typename PtRingType>
        inline void decryptionScale(const DCRTPoly<RingType, numLimbs>& dcrt_poly, poly<PtRingType>& result) const 
        /*
        Performs the "divide and round" step of decryption over DCRT limbs
        For a DCRT polynomial with limbs (q_1, ... , q_n) with representing m*q/t + e, where q = q_1 * ... * q_n
        returns m mod t.
        In otherwords, multiplies by t/q
        */
        {
            constexpr ui32 phim = RingType::phim;
            poly<RingType> y;            
            y.zeros();
            for (ui32 k = 0; k < phim; k++) {
                // ASSERT_DEBUG(y[k] == 0);
                for (ui32 i = 0; i < numLimbs; i++)
                    y[k] += mod_mul_slow(dcrt_poly.vals[i][k], decryptScaleConsts[i], t);
                y[k] = mod_slow(y[k], t);
                float_type v = 0;
                for (ui32 i = 0; i < numLimbs; i++)
                    v += ((float_type)dcrt_poly.vals[i][k]) * decryptScaleFloats[i];
                y[k] += (ui64)round(v);
                y[k] = mod_slow(y[k], t);
            }

            for (ui32 i = 0; i < phim; i++)
                result[i] = y[i];
        };

        template <typename RingType>
        inline Matrix<value_type> multiplicationScale(const DCRTPoly<RingType, numLimbs+numExtLimbs>& dcrt_poly) const 
        /*
        Scales down the product ciphertext by delta to turn Delta*m_1*Delta*m_2 into Delta*m_1*m_2
        */
        {
            constexpr ui32 phim = RingType::phim;

            Matrix<value_type> result(numExtLimbs, phim);
            // Matrix<T> result(numExtLimbs, phim);

            for (ui32 k = 0; k < phim; k++) {

                for (ui32 j = 0; j < numExtLimbs; j++) {
                    ui32 modInd = j + numLimbs;
                    greater_value_type newBasisTerm = (greater_value_type)dcrt_poly[modInd][k] * (greater_value_type)multScaleExtender[j];

                    greater_value_type toAddPrec = 0;
                    greater_value_type toAddPrecFloatInt = 0;
                    greater_value_type toAddPrecFloatSmall = 0;
                    #pragma clang loop vectorize(enable) interleave(enable)
                    for (ui32 i = 0; i < numLimbs; i++) {
                        toAddPrec += (greater_value_type)dcrt_poly[i][k] * (greater_value_type)multScaleConsts[j][i];
                        toAddPrecFloatInt += ((greater_value_type)dcrt_poly[i][k]) * ((greater_value_type)multScaleFloatInts[j][i]);
                        toAddPrecFloatSmall += dcrt_poly[i][k] * multScaleFloatsLow[j][i];
                    }

                    greater_value_type toAddPrecRounded = toAddPrec + ((toAddPrecFloatInt + toAddPrecFloatSmall)/FLOAT_SCALE);
                    newBasisTerm += toAddPrecRounded;
                    result[j][k] = newBasisTerm % IntRingType::getModulus(modInd);
                }

            }

            return result;
        }

        template <typename RingType>
        inline Matrix<value_type> discardOrig(const DCRTPoly<RingType, numLimbs+numExtLimbs>& dcrt_poly) const {
            constexpr ui32 phim = RingType::phim;
            Matrix<value_type> result(numExtLimbs, phim);
            for (ui32 i = numLimbs; i < numLimbs+numExtLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    result[i-numLimbs][j] = dcrt_poly.vals[i][j];

            return result;
        };

        template <typename RingType>
        inline DCRTPoly<RingType, numLimbs> discardExtension(const DCRTPoly<RingType, numLimbs+numExtLimbs>& dcrt_poly) const {
            constexpr ui32 phim = RingType::phim;
            DCRTPoly<RingType, numLimbs> result;
            for (ui32 i = 0; i < numLimbs; i++)
                // #pragma clang loop vectorize(enable) interleave(enable)
                for (ui32 j = 0; j < phim; j++)
                    result.vals[i][j] = dcrt_poly.vals[i][j];

            return result;
        };

        template <typename RingType>
        DCRTPoly<RingType, numLimbs> fullMultScale(const DCRTPoly<RingType, numLimbs+numExtLimbs>& toScaleDown) const {
            auto scaledDown = this->multiplicationScale(toScaleDown);
            DCRTPoly<RingType, numLimbs+numExtLimbs> revBasisExt;
            this->reverseExtendBasis(scaledDown, revBasisExt);
            return this->discardExtension(revBasisExt);
        };


        template <typename RingType>
        poly<RingType> compressDCRTPoly(const DCRTPoly<RingType, numLimbs>& toCompress) const 
        /*
        Complete mod reduction. Reduces a multi-limb ciphertext down to a single limb
        */
        {
            poly<RingType> result;
            constexpr ui32 phim = RingType::phim;
            // TODO: Benchmark looping in other order
         
            for (ui32 i = 0; i < phim; i++) {
                value_type toMod = 0;
                for (ui32 j = 0; j < numLimbs; j++)
                    toMod += (value_type)(
                                ((greater_value_type)
                                    IntRingType::mod_mul_shoup(toCompress[j][i], qi_tilde[j], qi_tilde_Shoup[j], IntRingType::getModulus(j))
                                ) * ((greater_value_type)IntRingType::getModulus(0))
                            / IntRingType::getModulus(j));

                result[i] = IntRingType::mod(toMod, 0);
            }

            // for (ui32 j = 0; j < numLimbs; j++) {
            //     for (ui32 i = 0; i < phim; i++) {
            //         result[i] += (value_type)(
            //                     ((greater_value_type)
            //                         IntRingType::mod_mul_shoup(toCompress[j][i], qi_tilde[j], qi_tilde_Shoup[j], IntRingType::getModulus(j))
            //                     ) * ((greater_value_type)IntRingType::getModulus(0))
            //                 / IntRingType::getModulus(j));
            //     }
            // }

            // for (ui32 i = 0; i < phim; i++) 
            //     result[i] = IntRingType::mod(result[i], 0);

            return result;
        };

        template <typename DCRTPolyType>
        typename DCRTPolyType::ReducedType scaleDownModulus(const DCRTPolyType& input, const typename DCRTPolyType::ReducedType& toSub) const
        /*
        Equivalent to the rescaleBy function in FullRNS-HEAAN. 
        Divides the polynomial by the smallest (last) modulus and returns the coefficients in the reduced base. 
        */
        {
            // ASSERT_DEBUG(nLimbs <= numLimbs);
            // ASSERT_DEBUG(1 < nLimbs);
            typedef typename DCRTPolyType::ReducedType ReducedType;
            constexpr ui32 phim = DCRTPolyType::phim;
            constexpr ui32 nLimbs = DCRTPolyType::numLimbs;
            static_assert(nLimbs <= numLimbs, "Number of limbs exceeds DCRTParmas limbs");
            static_assert(nLimbs > 1, "Number of limbs must be at least 2");
            ReducedType result;
            for (ui32 limbInd = 0; limbInd < nLimbs-1; limbInd++) {
                for (ui32 i = 0; i < phim; i++) {
                    value_type toLoad = IntRingType::mod(input[limbInd][i] + IntRingType::getModulus(limbInd) - toSub[limbInd][i], limbInd);
                    result[limbInd][i] = IntRingType::mod_mul_shoup(
                        toLoad, 
                        inversesModqi[limbInd][nLimbs-1],
                        inversesModqi_shoup[limbInd][nLimbs-1],
                        IntRingType::getModulus(limbInd)
                    );
                }
            }
            return result;
        };

        // template <typename RingType, ui32 numResLimbs>
        // void scaleDownExtModulus(DCRTPoly<RingType, numResLimbs>& result, const DCRTPoly<RingType, numResLimbs+numExtLimbs>& input) const
        // /*
        // Equivalent to the rescaleBy function in FullRNS-HEAAN. 
        // Divides the polynomial by the smallest (last) modulus and returns the coefficients in the reduced base. 
        // */
        // {
        //     ASSERT_DEBUG(numResLimbs <= numLimbs);
        //     constexpr ui32 phim = RingType::phim;
        //     // ASSUMPTION: Convert to sub-basis requires no change to limbs
        //     // Not an assumption made in paper...
        //     for (ui32 limbInd = 0; limbInd < numResLimbs; limbInd++) {
        //         for (ui32 i = 0; i < phim; i++) {
        //             value_type toLoad = IntRingType::mod(input[limbInd+numExtLimbs][i] + IntRingType::getModulus(limbInd) - input[limbInd][i], limbInd);
        //             result[limbInd][i] = IntRingType::mod_mul_shoup(
        //                 toLoad, 
        //                 PinverseModqi[limbInd],
        //                 PinverseModqi_shoup[limbInd],
        //                 IntRingType::getModulus(limbInd)
        //             );
        //         }
        //     }
        // };

        template <typename DCRTPolyTypeIn, typename DCRTPolyTypeOut>
        static inline void modDown(DCRTPolyTypeOut& result, const DCRTPolyTypeIn& input)
        /*
        Drops the last nLimbs_out - nLimbs_in moduli
        */
        {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Weverything"

            typedef typename DCRTPolyTypeIn::RingType RingType;
            static_assert(std::is_same<typename DCRTPolyTypeOut::RingType, RingType>::value, "RingType must be the same");
            constexpr ui32 nLimbs_in = DCRTPolyTypeIn::numLimbs;
            constexpr ui32 nLimbs_out = DCRTPolyTypeOut::numLimbs;
            static_assert(nLimbs_in >= nLimbs_out, "modDown: nLimbs_out cannot be greater than nLimbs_in");
            constexpr ui32 phim = RingType::phim;
            // DCRTPoly<RingType, nLimbs_out> result;
            #pragma clang loop vectorize(enable) interleave(enable)
            for (ui32 limbInd = 0; limbInd < nLimbs_out; limbInd++)
                #pragma clang loop vectorize(enable) interleave(enable)
                for (ui32 i = 0; i < phim; i++)
                    result[limbInd][i] = input[limbInd][i];

            #pragma clang diagnostic pop
            
        };
    };

    template <typename IntRingType, ui64 t>
    class DCRT_Fast_Two_Limb_Reduction_Params : public DCRT_Params<IntRingType, 2, 0, t> {
    public:

        using value_type = typename IntRingType::value_type;

        DCRT_Fast_Two_Limb_Reduction_Params() {
            static_assert(IntRingType::getModulus(0) == 2*IntRingType::getModulus(1)-1, "two-limb fast reduction conditions not satisfied");
            static_assert(std::is_same<typename IntRingType::ParamsType, fast_two_limb_reduction_params>::value, "incorrect params");
        };

        template <typename RingType>
        poly<RingType> compressDCRTPoly(const DCRTPoly<RingType, 2>& toCompress) const {
            poly<RingType> result;
            constexpr ui32 phim = RingType::phim;
            for (ui32 i = 0; i < phim; i++) {
                value_type toMod = (toCompress[0][i] >= toCompress[1][i]) ? 
                    (toCompress[0][i] - toCompress[1][i]) << 1 :
                    IntRingType::getModulus(0) - (toCompress[1][i] - toCompress[0][i])<<1;
                STRICT_MOD(toMod, IntRingType::getModulus(0));
                result[i] = toMod;
            }
            return result;
        };
    };

    template <typename IntRingType, ui64 t>
    class DCRT_Fast_Three_Limb_Reduction_Params : public DCRT_Params<IntRingType, 3, 0, t> {
    public:

        using value_type = typename IntRingType::value_type;
        using greater_value_type = typename IntRingType::greater_value_type;

        static constexpr value_type limb0Factor = IntRingType::mod(
            ((greater_value_type)8)*((greater_value_type)mod_inv(3, IntRingType::getModulus(0))), 0
        );
        static constexpr value_type limb2Factor = IntRingType::mod(
            ((greater_value_type)4)*((greater_value_type)mod_inv(3, IntRingType::getModulus(2))) 
            - ((greater_value_type)2), 0
        );
        static constexpr value_type avoidUnderflow = 
            (limb0Factor + limb2Factor >= 4*IntRingType::getModulus(1)) ? 0 : 3*IntRingType::getModulus(0);

        DCRT_Fast_Three_Limb_Reduction_Params() {
            static_assert(IntRingType::getModulus(0) == 2*IntRingType::getModulus(1)-1, 
                "three-limb fast reduction conditions not satisfied");
            static_assert(IntRingType::getModulus(1) == 2*IntRingType::getModulus(2)-1, 
                "three-limb fast reduction conditions not satisfied");   
            static_assert(IntRingType::ParamsType::kMaxNbModuli == 3, "incorrect number of limbs");
        };

        template <typename RingType>
        poly<RingType> compressDCRTPoly(const DCRTPoly<RingType, 3>& toCompress) const {
            poly<RingType> result;
            constexpr ui32 phim = RingType::phim;
            ui32 i;
            // #pragma omp parallel for private(i)
            for (i = 0; i < phim; i++) {
                greater_value_type toMod = 
                    ((greater_value_type)limb0Factor)*((greater_value_type)toCompress[0][i]) 
                    + ((greater_value_type)limb2Factor)*((greater_value_type)toCompress[2][i])
                    + avoidUnderflow - (greater_value_type)(4*toCompress[1][i]);
                result[i] = IntRingType::mod(toMod,0);
            }
            return result;
        };
    };


    template <typename IntRingType, ui64 t>
    class DCRT_Fast_Four_Limb_Reduction_Params : public DCRT_Params<IntRingType, 4, 0, t> {
    public:

        using value_type = typename IntRingType::value_type;
        using greater_value_type = typename IntRingType::greater_value_type;

        static constexpr value_type limb0Factor = IntRingType::mod(
            ((greater_value_type)64)*((greater_value_type)mod_inv(21, IntRingType::getModulus(0))), 0
        );
        static constexpr value_type limb1Factor = IntRingType::mod(
            IntRingType::getModulus(1) -
            ((greater_value_type)8)*((greater_value_type)mod_inv(3, IntRingType::getModulus(1))), 1
        );
        static constexpr value_type limb2Factor = IntRingType::mod(
            ((greater_value_type)2)*((greater_value_type)mod_inv(3, IntRingType::getModulus(2))), 2
        );
        static constexpr value_type limb3Factor = IntRingType::mod(
            // ((greater_value_type)8)*
            ((greater_value_type)mod_inv(IntRingType::getModulus(3) - 21, IntRingType::getModulus(3))), 3
        );

        DCRT_Fast_Four_Limb_Reduction_Params() {
            static_assert(IntRingType::getModulus(0) == 2*IntRingType::getModulus(1)-1, 
                "four-limb fast reduction conditions not satisfied");
            static_assert(IntRingType::getModulus(1) == 2*IntRingType::getModulus(2)-1, 
                "four-limb fast reduction conditions not satisfied");
            static_assert(IntRingType::getModulus(2) == 2*IntRingType::getModulus(3)-1, 
                "four-limb fast reduction conditions not satisfied");   
            static_assert(IntRingType::ParamsType::kMaxNbModuli == 4, "incorrect number of limbs");
        };

        template <typename RingType>
        poly<RingType> compressDCRTPoly(const DCRTPoly<RingType, 4>& toCompress) const {
            poly<RingType> result;
            constexpr ui32 phim = RingType::phim;
            for (ui32 i = 0; i < phim; i++) {
                // if (i==0) {
                //     for (ui32 j = 0; j < 4; j++)
                //         cout << toCompress[j][i] << " ";
                //     cout << endl;
                //     cout << "q0_tilde = " << limb0Factor << " " << this->qi_tilde[0] << endl
                //         << "q1_tilde = " << limb1Factor << " " << this->qi_tilde[1] << endl
                //         << "q2_tilde = " << limb2Factor << " " << this->qi_tilde[2] <<  endl 
                //         << "q3_tilde = " << limb3Factor << " " << this->qi_tilde[3] << endl;
                //     cout << "limb0 " << IntRingType::mod_mul(limb0Factor, toCompress[0][i], 0) << endl
                //     << "limb1 " << IntRingType::mod_mul(limb1Factor, toCompress[1][i], 1)*2 << endl
                //     << "limb2 " << IntRingType::mod_mul(limb2Factor, toCompress[2][i], 2)*4 << endl
                //     << "limb3 " << IntRingType::mod_mul(limb2Factor, toCompress[3][i], 3)*8 << endl;
                // }
                // // greater_value_type toMod = 
                // //     // ((greater_value_type)limb0Factor)*((greater_value_type)toCompress[0][i]) 
                // //     IntRingType::mod_mul(limb0Factor, toCompress[0][i], 0)
                // //     // + ((greater_value_type)limb1Factor)*((greater_value_type)toCompress[1][i])<<1 
                // //     + IntRingType::mod_mul(limb1Factor, toCompress[1][i], 1)*2 
                // //     // + ((greater_value_type)limb2Factor)*((greater_value_type)toCompress[2][i])<<2
                // //     + IntRingType::mod_mul(limb2Factor, toCompress[2][i], 2)*4 
                // //     // + ((greater_value_type)limb3Factor)*((greater_value_type)toCompress[3][i])<<3;
                // //     + IntRingType::mod_mul(limb3Factor, toCompress[3][i], 3)*8;
                greater_value_type toMod = 0;
                for (ui32 j = 0; j < 4; j++) {
                    toMod += IntRingType::mod_mul(this->qi_tilde[j], toCompress[j][i], j)*(1<<j); 
                }
                result[i] = IntRingType::mod(toMod,0);
            }
            return result;
        };
    };

}  // namespace lbcrypto ends

#endif
