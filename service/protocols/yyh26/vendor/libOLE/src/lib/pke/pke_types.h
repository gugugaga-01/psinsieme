/*
    Defines common structs for pke schemes
*/

#ifndef LBCRYPTO_PKE_PKE_TYPES_H
#define LBCRYPTO_PKE_PKE_TYPES_H

#include "math/poly.h"

namespace lbcrypto {

    //
    // Keys
    //

    template <typename PolyType>
    struct SecretKey {
        PolyType s;
        SecretKey() {};
        SecretKey(PolyType s_in) : s(s_in) {};
    };

    template <typename PolyType>
    struct PublicKey {
        PolyType a;
        PolyType b;
        PublicKey() {};
        PublicKey(PolyType a_in, PolyType b_in) : a(a_in), b(b_in) {};
    };

    template <typename PolyType>
    struct KeyPair {
        SecretKey<PolyType> sk;
        PublicKey<PolyType> pk;
        KeyPair(){};
    };

    template <typename DCRTPolyType>
    struct SecretKeyDCRT {
        DCRTPolyType s;
        DCRTPolyType sShoup;
        SecretKeyDCRT() {};
        SecretKeyDCRT(DCRTPolyType s_in) : s(s_in) {};
    };

    template <typename DCRTPolyType>
    struct PublicKeyDCRT {
        DCRTPolyType a;
        DCRTPolyType aShoup;
        DCRTPolyType b;
        DCRTPolyType bShoup;
        PublicKeyDCRT(){};
        // PublicKeyDCRT(const DCRTPolyType& a_in, DCRTPolyType& b_in) : a(a_in), b(b_in) {};
    };

    template <typename DCRTPolyType>
    struct PublicKeyDCRTSeeded {
        osuCryptoNew::block seed;
        DCRTPolyType b;
        PublicKeyDCRTSeeded() {};

        PublicKeyDCRT<DCRTPolyType> expand() {
            PublicKeyDCRT<DCRTPolyType> result;
            result.a = DCRTPolyType(seed);
            result.aShoup = result.a.compute_shoup();
            result.b = b;
            result.bShoup = b.compute_shoup();
            return result;
        };
    };

    template <typename DCRTPolyType>
    struct KeyPairDCRT {
        SecretKeyDCRT<DCRTPolyType> sk;
        PublicKeyDCRT<DCRTPolyType> pk;
        KeyPairDCRT(){};
        KeyPairDCRT(const SecretKeyDCRT<DCRTPolyType>& sk_in, const PublicKeyDCRT<DCRTPolyType>& pk_in) : sk(sk_in), pk(pk_in){};
        KeyPairDCRT(const PublicKeyDCRT<DCRTPolyType>& pk_in, const SecretKeyDCRT<DCRTPolyType>& sk_in) : KeyPairDCRT(sk_in, pk_in){};
        KeyPairDCRT(const KeyPairDCRT<DCRTPolyType>& kp) : KeyPairDCRT(kp.sk, kp.pk) {};
    };

    template <typename DCRTPolyType>
    struct KeyPairDCRTSeeded {
        SecretKeyDCRT<DCRTPolyType> sk;
        PublicKeyDCRTSeeded<DCRTPolyType> pkSeeded;
        KeyPairDCRTSeeded(){};
        KeyPairDCRTSeeded(const SecretKeyDCRT<DCRTPolyType>& sk_in, const PublicKeyDCRTSeeded<DCRTPolyType>& pk_in) : sk(sk_in), pkSeeded(pk_in){};
        KeyPairDCRTSeeded(const PublicKeyDCRTSeeded<DCRTPolyType>& pk_in, const SecretKeyDCRT<DCRTPolyType>& sk_in) : KeyPairDCRTSeeded(sk_in, pk_in){};
        KeyPairDCRTSeeded(const KeyPairDCRTSeeded<DCRTPolyType>& kp) : KeyPairDCRTSeeded(kp.sk, kp.pkSeeded) {};
    };

    //
    // Ciphertext
    //

    template <typename PolyType>
    struct DCRT_Seeded_Ciphertext;

    template <typename DCRTPoly_in>
    struct DCRT_Ciphertext {
        
        typedef DCRTPoly_in DCRTPoly;
        typedef DCRT_Ciphertext<typename DCRTPoly::ReducedType> ReducedType;

        typedef DCRT_Seeded_Ciphertext<DCRTPoly> SeededType;

        static constexpr ui32 phim = 1<<DCRTPoly::logn;
        static constexpr ui32 numLimbs = DCRTPoly::numLimbs;

        DCRTPoly a, b;

        DCRT_Ciphertext() {};
        DCRT_Ciphertext(const DCRT_Ciphertext<DCRTPoly>& other) {
            a = DCRTPoly(other.a);
            b = DCRTPoly(other.b);
        };

        template <class Archive>
        void serialize(Archive& ar, const ui32 version) {
            ar & a;
            ar & b;
        };

        bool operator==(const DCRT_Ciphertext<DCRTPoly>& o) const {
            return (a == o.a && b == o.b);
        };

        DCRT_Ciphertext<DCRTPoly>& operator=(const DCRT_Ciphertext<DCRTPoly>& o) {
            a = o.a;
            b = o.b;
            return *this;
        };

        static ui32 getNumBytes() {
            return 2*DCRTPoly::getNumBytes();
        };
    };

    template <typename poly>
    struct Single_Limb_Ciphertext {

        static constexpr ui32 phim = poly::phim;

        poly a, b;

        Single_Limb_Ciphertext() {};
        Single_Limb_Ciphertext(const Single_Limb_Ciphertext<poly>& other) {
            a = poly(other.a);
            b = poly(other.b);
        };

        template <typename DCRTPolyType, typename = enable_if_t<DCRTPolyType::numLimbs == 1>>
        Single_Limb_Ciphertext(const DCRT_Ciphertext<DCRTPolyType>& other) {
            ASSERT_DEBUG(DCRTPolyType::numLimbs == 1);
            a = poly(other.a[0]);
            b = poly(other.b[0]);
        };

        bool operator==(const Single_Limb_Ciphertext<poly>& o) {
            return (a == o.a && b == o.b);
        };
    };

    template <typename DCRTPoly_in>
    struct DCRT_Seeded_Ciphertext {

        typedef DCRTPoly_in DCRTPoly;

        typedef DCRT_Ciphertext<DCRTPoly> UnSeededType;

        static constexpr ui32 phim = 1<<DCRTPoly::logn;
        static constexpr ui32 numLimbs = DCRTPoly::numLimbs;

        osuCryptoNew::block seed;
        DCRTPoly b;

        DCRT_Seeded_Ciphertext() {};
        DCRT_Seeded_Ciphertext(const DCRT_Seeded_Ciphertext<DCRTPoly>& other) {
            seed = other.seed;
            b = DCRTPoly(other.b);
        };

        template <class Archive>
        void serialize(Archive& ar, const ui32 version) {
            ar & seed;
            ar & b;
        };

        bool operator==(const DCRT_Seeded_Ciphertext<DCRTPoly>& o) const {
            return (seed == o.seed && b == o.b);
        };

        DCRT_Ciphertext<DCRTPoly> expand() const {        
            DCRT_Ciphertext<DCRTPoly> result;
            result.a = DCRTPoly(seed);
            result.b = b;
            return result;
        };

        static ui32 getNumBytes() {
            return DCRTPoly::getNumBytes() + 16;  // 128 bit seed
        };
    };

}  // namespace lbcrypto ends

#endif
