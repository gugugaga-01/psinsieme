/*
    Implementation of BFVrns
*/

#ifndef LBCRYPTO_PKE_BFV_H
#define LBCRYPTO_PKE_BFV_H

#include "math/encoding.h"
#include "pke_types.h"
#include "math/discretegaussiangenerator.h"
#include "utils/test.h"


namespace lbcrypto {

    //
    // Main Scheme
    //

    // class BFV_DCRT_Base {};

    template<typename EncodingType, typename DCRTParamsType_in>
    class BFV_DCRT {
    public:

        /** Basic Types **/
        typedef DCRTParamsType_in DCRTParamsType;

        using plaintext_type = typename EncodingType::value_type;
        using value_type = typename DCRTParamsType::value_type;
        using greater_value_type = typename DCRTParamsType::greater_value_type;

        /** Static Parameters **/

        static constexpr ui32 numLimbs = DCRTParamsType::numLimbs;
        static constexpr ui32 numExtLimbs = DCRTParamsType::numExtLimbs;

        static constexpr ui32 logn = EncodingType::logn;
        static constexpr ui32 phim = 1<<logn;
        static constexpr ui32 dataLength = phim;

        static constexpr plaintext_type plaintextModulus = EncodingType::modulus;

        // Polys
        using RingType = typename DCRTParamsType::IntRingType::template PolyRingTypeGetter<logn>::PolyRingType;
        typedef DCRTPoly<RingType, numLimbs+numExtLimbs> DCRTPolyExt;
        typedef DCRTPoly<RingType, numLimbs> DCRTPoly;

        typedef MultiLimb_NTT_Context<RingType, numLimbs+numExtLimbs> NTT_Context_Type;

        // encoding context encodes to and decodes from ptPoly
        using ptPoly = typename EncodingType::ptPoly;
        typedef poly<RingType> poly;

        /**Crypto Types **/

        // Keys
        typedef KeyPairDCRT<DCRTPoly> KeyPair;
        typedef KeyPairDCRTSeeded<DCRTPoly> KeyPairSeeded;
        typedef SecretKeyDCRT<DCRTPoly> SecretKey;
        typedef PublicKeyDCRT<DCRTPoly> PublicKey;
        typedef PublicKeyDCRTSeeded<DCRTPoly> PublicKeySeeded;

        // Ciphertexts
        typedef DCRT_Ciphertext<DCRTPoly> Ciphertext;
        typedef Single_Limb_Ciphertext<poly> CompressedCiphertext;
        typedef DCRT_Seeded_Ciphertext<DCRTPoly> SeededCiphertext;

        // Encoding
        // encoding context encodes from and decodes to encoding_input_t
        using encoding_input_t = typename EncodingType::encoding_input_t;
        typedef EncodingType encoding_context_t;


        /** (mostly) Nonstatic Parameters **/

        const double std_dev;
        const DiscreteGaussianGenerator dgg;
        std::vector<value_type> deltas;
        static constexpr value_type deltaSmall = RingType::getModulus(0)/plaintextModulus;

        /** Define Modules **/
        static const DCRTParamsType dcrt_params;
        static const EncodingType encoding_context;
        static const NTT_Context_Type ntt_context;

        /** Setup functions **/


        BFV_DCRT(double s_d = 3.2, ui32 w_sz = 2, ui32 pt_w_sz = 2) : std_dev(s_d), dgg(s_d) {

            static_assert(
                EncodingType::modulus == DCRTParamsType::plaintextModulus,
                "Encoding modulus is different from DCRT params plaintext modulus"
            );

            ubi bigQ = 1;
            for (ui32 i = 0; i < numLimbs; i++)
                bigQ = bigQ * ubi(RingType::getModulus(i));
            ubi bigDelta = bigQ/ubi(plaintextModulus);
            for (ui32 i = 0; i < numLimbs; i++)
                deltas.push_back((bigDelta % ubi(RingType::getModulus(i))).toUnsignedLong());
        };

        static constexpr inline value_type compute_shoup(const value_type in, const value_type modulus) {
            return ((greater_value_type)in << RingType::getModulusRepresentationBitSize()) / modulus;
        };

        static constexpr inline DCRTPoly compute_shoup(const DCRTPoly& input) {
            DCRTPoly result;
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    result.vals[i][j] = compute_shoup(input.vals[i][j], RingType::getModulus(i));
            return result;
        };

        static constexpr inline void compute_shoup(DCRTPoly& result, const DCRTPoly& input) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    result.vals[i][j] = compute_shoup(input.vals[i][j], RingType::getModulus(i));
        };

       
        template <typename DCRTPolyType>
        static typename DCRTPolyType::ReducedType scaleDownModulus(const DCRTPolyType& input, const bool verbose = false) {
            using ReducedType = typename DCRTPolyType::ReducedType;
            ASSERT_DEBUG(input.checkSelfReduced());
            
            DCRTPolyType inputCoeffs(input);
            // inputCoeffs.ToCoeff(ntt_context);

            uvbi bigInputCoeffs = reconstructDCRTPoly(inputCoeffs);

            ubi qL = ubi(RingType::getModulus(input.numLimbs-1));

            // a.divideWithRemainder(b, q)' is like `q = a / b, a %= b'.
            ubi quot;
            for (ui32 i = 0; i < phim; i++) {
                bigInputCoeffs[i].divideWithRemainder(qL, quot);
                const bool addOne = bigInputCoeffs[i] > qL/ubi(2);
                bigInputCoeffs[i] = quot;
                if (addOne) bigInputCoeffs[i] += ubi(1);
            }

            ReducedType result(bigInputCoeffs);
            result.ToEval(ntt_context);
            return result;
        }

        template <typename CiphertextType>
        static typename CiphertextType::ReducedType scaleDownCiphertext(const CiphertextType& input, const bool verbose = false) {
            using ReducedType = typename CiphertextType::ReducedType;
            ReducedType result;
            result.a = scaleDownModulus(input.a);
            result.b = scaleDownModulus(input.b, verbose);
            return result;
        }

        /** PKE **/

        inline DCRTPoly packed_encode(const encoding_input_t& x) const {
            ptPoly pt_arr = encoding_context.packed_encode(x);
            DCRTPoly pt(pt_arr, true);
            return pt;
        }

        template<typename DCRTPolyType>
        void inline sample_error(DCRTPolyType& x) const {
        // void inline sample_error(DCRTPoly& x, const bool debug=true) const {
            // if (debug) { x.zeros(); std::cout << "CHANGE ME BACK!\n"; return; }
            dgg.LoadVectorDCRT<typename DCRTPolyType::RingType, DCRTPolyType::numLimbs>(x);
        }

        void inline sample_error(poly& x) const {
            dgg.LoadVectorPoly<RingType, poly::modInd>(x);
        }


        KeyPair KeyGen() const {
            KeyPair result;

            // SecretKey sk;`
            SecretKey& sk = result.sk;
            // sk.s.ones(); std::cout << "CHANGE ME BACK!\n";
            sample_error(sk.s);
            sk.s.ToEval(ntt_context);
            compute_shoup(sk.sShoup, sk.s);

            PublicKey& pk = result.pk;
            pk.a.random();
            compute_shoup(pk.aShoup, pk.a);
            sample_error(pk.b);
            pk.b.ToEval(ntt_context);
            mod_mul_shoup_sub(pk.b, pk.a, sk.s, sk.sShoup);
            compute_shoup(pk.bShoup, pk.b);

            return result;
        };

        KeyPairSeeded KeyGenSeeded(const bool useSeed = false, const osuCryptoNew::block& seed = osuCryptoNew::ZeroBlock) const {
            KeyPairSeeded result;

            SecretKey& sk = result.sk;
            // sk.s.ones(); std::cout << "CHANGE ME BACK!\n";
            sample_error(sk.s);
            sk.s.ToEval(ntt_context);
            compute_shoup(sk.sShoup, sk.s);

            PublicKeySeeded& pk = result.pkSeeded;
            
            if (useSeed) pk.seed = seed;
            else pk.seed = osuCryptoNew::sysRandomSeed();

            DCRTPoly a = DCRTPoly(pk.seed);
            sample_error(pk.b);
            pk.b.ToEval(ntt_context);
            mod_mul_shoup_sub(pk.b, a, sk.s, sk.sShoup);

            return result;
        };

        inline void Decrypt_NoDecode(plaintext_type discrim, ptPoly& result, const SecretKey& sk, const Ciphertext& ct) const {
            DCRTPoly toScale = mod_mul_shoup(ct.a, sk.s, sk.sShoup) + ct.b;
            toScale.ToCoeff(ntt_context);
            dcrt_params.decryptionScale(toScale, result);
        };

        inline void Decrypt_NoDecode(ui32 discrim, ptPoly& result, const SecretKey& sk, const CompressedCiphertext& ct) const {
            poly s_q1(sk.s.vals[0]);
            poly as_q1 = ct.a * s_q1;
            as_q1.ToCoeff(ntt_context.ntt_contexts[0]);

            poly toScaleDown = as_q1 + ct.b;

            for (ui32 i = 0; i < phim; i++) {
                result[i] = (plaintext_type)(toScaleDown[i] / deltaSmall);
                // result[i] = (plaintext_type)round((fl64)toScaleDown[i] / (fl64)deltaSmall);
                // if (result[i] == plaintextModulus) result[i] = 0;
            }
        };

        inline void Decrypt_NoDecode(ui64 discrim, ptPoly& result, const SecretKey& sk, const CompressedCiphertext& ct) const {
            poly s_q1(sk.s.vals[0]);
            poly as_q1 = ct.a * s_q1;
            as_q1.ToCoeff(ntt_context.ntt_contexts[0]);

            poly toScaleDown = as_q1 + ct.b;

            ui32 i;
            // #pragma omp parallel for private(i)
            for (i = 0; i < phim; i++) {
                fl128 floatDec = 
                    (fl128)plaintextModulus * (fl128)toScaleDown[i] / (fl128)RingType::getModulus(0);
                plaintext_type resVal = (plaintext_type)floatDec;
                if (floatDec - resVal >= 0.5) resVal++;
                result[i] = resVal;
                if (result[i] == plaintextModulus) result[i] = 0;
            }
        };

        template <typename CiphertextType>
        encoding_input_t Decrypt(const SecretKey& sk, const CiphertextType& ct) const {
            ptPoly result;
            // typename ptPoly::value_type discrim = (typename ptPoly::value_type)1;
            // Decrypt_NoDecode(discrim, result, sk, ct);
            Decrypt_NoDecode((ui64)1, result, sk, ct);
            return encoding_context.packed_decode(result);
        };

        ui32 NoiseMargin(const SecretKey& sk, const Ciphertext& ct) const {
            auto message = Decrypt(sk, ct);
            DCRTPoly toSub = mod_mul_shoup(ct.a, sk.s, sk.sShoup) + ct.b;
            toSub.ToCoeff(ntt_context);

            DCRTPoly toScale = packed_encode(message);
            toScale *= deltas;

            DCRTPoly toRecon = toSub - toScale;

            auto bigNoise = reconstructDCRTPoly(toRecon);

            ubi bigQ = getBigQ(numLimbs);

            ui32 result = 0;
            for (ui32 i = 0; i < bigNoise->size(); i++) {
                ubi currNoise = bigNoise[i];
                if (currNoise > bigQ/2)
                    currNoise = bigQ - currNoise;
                result = std::max(result, currNoise.bitLength());
            }

            return result;
        };

        ui32 NoiseMargin(const SecretKey& sk, const CompressedCiphertext& ct) const {
            poly message = Decrypt(sk, ct);
            poly s_q1(sk.s.vals[0]);
            poly as_q1 = ct.a * s_q1;
            as_q1.ToCoeff(ntt_context.ntt_contexts[0]);

            poly toSub = as_q1 + ct.b;
            poly toScale(packed_encode(message).vals[0]);
            toScale *= deltaSmall;

            poly noise = toSub - toScale;

            ui32 result = 0;
            constexpr value_type q0 = RingType::getModulus(0);
            for (ui32 i = 0; i < phim; i++) {
                ui64 currNoise = noise[i];
                if (currNoise > q0/2)
                    currNoise = q0 - currNoise;
                result = std::max(result, (ui32)ceil(log2(currNoise)));
            }

            return 
                DCRTParamsType::IntRingType::ParamsType::getModulusBitSize(0) 
                - (ui32)ceil(log2(plaintextModulus)) - result;
        };

        Ciphertext Encrypt(const SecretKey& sk, const DCRTPoly& pt) const {
            Ciphertext result;
            result.a.random();
            sample_error(result.b);
            result.b.ToEval(ntt_context);
            result.b = result.b + pt - mod_mul_shoup(result.a, sk.s, sk.sShoup);

            return result;
        };

        SeededCiphertext EncryptSeeded(const SecretKey& sk, const DCRTPoly& pt) const {
            SeededCiphertext result;
            result.seed = osuCryptoNew::sysRandomSeed();
            // DCRTPoly a(result.seed);
            DCRTPoly a;
            // #pragma omp task default(shared)
            {
                a = DCRTPoly(result.seed);
            }
            sample_error(result.b);
            // result.b.zeros(); std::cout << "CHANGE ME BACK!\n";
            result.b.ToEval(ntt_context);
            // #pragma omp taskwait
            result.b = result.b + pt - mod_mul_shoup(a, sk.s, sk.sShoup);
            return result;
        };

        Ciphertext Encrypt(const SecretKey& sk, const encoding_input_t& x) const {
            DCRTPoly pt = packed_encode(x);
            pt *= deltas;
            pt.ToEval(ntt_context);
            return Encrypt(sk, pt);
        };

        // Ciphertext EncryptLimbScale(const SecretKey& sk, const encoding_input_t& x) const {
        //     DCRTPoly pt = packed_encode(x);
        //     // pt *= deltas;
        //     for (ui32 i = 0; i < numLimbs-1; i++) {
        //         pt *= RingType::getModulus(i+1);
        //     }
        //     pt.ToEval(ntt_context);
        //     return Encrypt(sk, pt);
        // };

        SeededCiphertext EncryptSeeded(const SecretKey& sk, const encoding_input_t& x) const {
            DCRTPoly pt = packed_encode(x);
            pt *= deltas;
            pt.ToEval(ntt_context);
            return EncryptSeeded(sk, pt);
        };

        Ciphertext Encrypt(const PublicKey& pk, const DCRTPoly& pt) const {
            DCRTPoly u, e, e_p;
            sample_error(u); u.ToEval(ntt_context);
            sample_error(e); e.ToEval(ntt_context);
            sample_error(e_p); e_p.ToEval(ntt_context);

            Ciphertext result;
            result.a = mod_mul_shoup(u, pk.a, pk.aShoup) + e;
            result.b = threeSum(mod_mul_shoup(u, pk.b, pk.bShoup), e_p, pt);

            return result;
        };

        template <typename DCRTPolyType>
        DCRT_Ciphertext<DCRTPolyType> EncryptSmall(const PublicKey& pk, const DCRTPolyType& pt) const {
            DCRTPolyType u, e, e_p;
            sample_error(u); u.ToEval(ntt_context);
            sample_error(e); e.ToEval(ntt_context);
            sample_error(e_p); e_p.ToEval(ntt_context);

            DCRT_Ciphertext<DCRTPolyType> result;
            result.a = mod_mul_shoup(u, pk.a, pk.aShoup) + e;
            result.b = threeSum(mod_mul_shoup(u, pk.b, pk.bShoup), e_p, pt);

            return result;
        };

        Ciphertext EncryptZero(const PublicKey& pk) const {
            DCRTPoly u, e, e_p;
            sample_error(u); u.ToEval(ntt_context);
            sample_error(e); e.ToEval(ntt_context);
            sample_error(e_p); e_p.ToEval(ntt_context);

            Ciphertext result;
            result.a = mod_mul_shoup(u, pk.a, pk.aShoup) + e;
            result.b = mod_mul_shoup(u, pk.b, pk.bShoup) + e_p;

            return result;
        };

        Ciphertext KDMEncrypt(const PublicKey& pk, const DCRTPoly& pt) const {
            Ciphertext result = EncryptZero(pk);
            result.a += pt;
            return result;
        };

        Ciphertext KDMEncrypt(const PublicKey& pk, const encoding_input_t& x) const {
            const auto pt = packed_encode(x);
            return KDMEncrypt(pk, pt);
        };

        Ciphertext Encrypt(const PublicKey& pk, const encoding_input_t& x) const {
            DCRTPoly pt = packed_encode(x);
            pt *= deltas;
            pt.ToEval(ntt_context);
            return Encrypt(pk, pt);
        };

        CompressedCiphertext CompressCiphertext(const Ciphertext& ct, const bool toCoeff=true, const bool toEval=true) const {
            DCRTPoly ct_a(ct.a);
            DCRTPoly ct_b(ct.b);
            if (toCoeff) {
                ct_a.ToCoeff(ntt_context);
                ct_b.ToCoeff(ntt_context);
            }
            CompressedCiphertext result;
            result.a = dcrt_params.compressDCRTPoly(ct_a);
            result.b = dcrt_params.compressDCRTPoly(ct_b);

            // Ready for decryption
            if (toEval)
                result.a.ToEval(ntt_context.ntt_contexts[0]);
                
            return result;
        };

        /** Basic Arithmetic **/

        Ciphertext EvalAdd(const Ciphertext& ct1, const Ciphertext& ct2) const {
            Ciphertext result;
            result.a = ct1.a + ct2.a;
            result.b = ct1.b + ct2.b;
            return result;
        };

        // Ciphertext or CompressedCiphertext
        template <typename CiphertextType>
        void EvalAddInPlace(CiphertextType& ct1, const CiphertextType& ct2) const {
            ct1.a += ct2.a;
            ct1.b += ct2.b;
        };

        Ciphertext EvalSub(const Ciphertext& ct1, const Ciphertext& ct2) const {
            Ciphertext result;
            result.a = ct1.a - ct2.a;
            result.b = ct1.b - ct2.b;
            return result;
        };

        void EvalSubInPlace(Ciphertext& ct1, const Ciphertext& ct2) const {
            ct1.a -= ct2.a;
            ct1.b -= ct2.b;
        };

        Ciphertext EvalSubPlain(const Ciphertext& ct, const DCRTPoly& pt, const bool scale = true) const {
            DCRTPoly scaled(pt);
            if (scale) scaled *= deltas;
            Ciphertext result;
            result.a = ct.a;
            result.b = ct.b - scaled;
            return result;
        }

        Ciphertext EvalSubPlain(const DCRTPoly& pt, const Ciphertext& ct, const bool scale = true) const {
            DCRTPoly scaled(pt);
            if (scale) scaled *= deltas;
            Ciphertext result;
            result.a = ct.a;
            result.a.negate();
            result.b = scaled - ct.b;
            return result;
        };

        inline void EvalSubPlainInPlace(Ciphertext& ct, const DCRTPoly& pt) const {
            ct.b -= pt;
        };

        Ciphertext EvalAddPlain(const Ciphertext& ct, const DCRTPoly& pt, const bool scale = true) const {
            DCRTPoly scaled(pt);
            if (scale) scaled *= deltas;
            Ciphertext result;
            result.a = ct.a;
            result.b = ct.b + scaled;
            return result;
        };

        Ciphertext EvalAddPlain(const Ciphertext& ct, const encoding_input_t& x, const bool encode = true) const {
            DCRTPoly pt = packed_encode(x);
            pt *= deltas;
            pt.ToEval(ntt_context);

            Ciphertext result;
            result.a = ct.a;
            result.b = ct.b + pt;

            return result;
        };

        // NOTE: Assume both ct.b and x are in COEFF representation
        CompressedCiphertext EvalAddPlain(const CompressedCiphertext& ct, const poly& x, const bool encode = true) const {
            CompressedCiphertext result;
            result.a = ct.a;
            result.b = ct.b + x;
            return result;
        }

        // Ciphertext or CompressedCiphertext
        template <typename CiphertextType>
        inline void EvalAddPlainInPlace(CiphertextType& ct, const DCRTPoly& pt) const {
            ct.b += pt;
        };

        DCRTPoly encodePlainMult(const ptPoly& x) const {
            ptPoly toEnc = encoding_context.packed_encode(x);
            DCRTPoly result(toEnc, true);
            result.ToEval(ntt_context);
            return result;
        };

        DCRTPoly encodePlainAdd(const ptPoly& x) const {
            DCRTPoly toScale = encodePlainMult(x);
            toScale *= deltas;
            return toScale;
        };

        encoding_input_t decodePlainAdd(const DCRTPoly& input) const {
            DCRTPoly toScaleDown(input);
            toScaleDown.ToCoeff(ntt_context);
            ptPoly scaledDown;
            dcrt_params.decryptionScale(toScaleDown, scaledDown);
            return encoding_context.packed_decode(scaledDown);
        };

        // Note: Assumes input poly is in coeff representation
        encoding_input_t decodePlainAdd(const poly& input) const {
            ptPoly scaledDown;
            for (ui32 i = 0; i < phim; i++) {
                scaledDown[i] = (plaintext_type)round((fl64)input[i] / (fl64)deltaSmall);
                if (scaledDown[i] == plaintextModulus) scaledDown[i] = 0;
            }
            scaledDown = encoding_context.packed_decode(scaledDown);
            return scaledDown;
        };

        Ciphertext EvalMultPlain(const Ciphertext& ct, const DCRTPoly& pt) const {
            Ciphertext result;
            result.a = ct.a * pt;
            result.b = ct.b * pt;
            return result;
        };

        Ciphertext EvalMultPlain(const Ciphertext& ct, const encoding_input_t& x, const bool encode = true) const {
            DCRTPoly pt = packed_encode(x);
            pt.ToEval(ntt_context);
            return EvalMultPlain(ct, pt);
        };

        inline void EvalMultPlainInPlace(Ciphertext& ct, const DCRTPoly& pt) const {
            ct.a *= pt;
            ct.b *= pt;
        };

    };

    /** Static variable initialization **/

    template<typename EncodingType, typename DCRTParamsType>
    const EncodingType BFV_DCRT<EncodingType, DCRTParamsType>::encoding_context = EncodingType();

    template<typename EncodingType, typename DCRTParamsType>
    const DCRTParamsType BFV_DCRT<EncodingType, DCRTParamsType>::dcrt_params = DCRTParamsType();

    template<typename EncodingType, typename DCRTParamsType>
    const typename BFV_DCRT<EncodingType, DCRTParamsType>::NTT_Context_Type BFV_DCRT<EncodingType, DCRTParamsType>::ntt_context =
        MultiLimb_NTT_Context<typename BFV_DCRT<EncodingType, DCRTParamsType>::RingType, DCRTParamsType::numLimbs + DCRTParamsType::numExtLimbs>();



}  // namespace lbcrypto ends

#endif
