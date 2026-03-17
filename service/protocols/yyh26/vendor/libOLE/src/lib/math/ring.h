/*
 * ring.h  --  Defines a Polynoial ring
 *      Merges NTT and DCRT operations engines
 *      Provides an additional layer of abstraction so we can easily define
 *      new parameter sets of the same data type
 */

#ifndef LBCRYPTO_MATH_RING_H
#define LBCRYPTO_MATH_RING_H

#include "params.h"
#include "nbtheory.h"

namespace lbcrypto {

    template <typename ParamsType, ui32 logn_in>
    class DCRT_Poly_Ring;

    template <typename ParamsType_in> 
    class DCRT_Ring {
    public:
        typedef ParamsType_in ParamsType;
        using value_type = typename ParamsType::value_type;
        using signed_value_type = typename ParamsType::signed_value_type;
        using greater_value_type = typename ParamsType::greater_value_type;

        template <ui32 logn>
        struct PolyRingTypeGetter {
            typedef DCRT_Poly_Ring<ParamsType, logn> PolyRingType;
        };

        static constexpr ui32 shift = ParamsType::kModulusRepresentationBitsize;
        static constexpr greater_value_type shiftMask = ((greater_value_type)1<<shift)-1;

        static constexpr value_type inline getModulus(const ui32 modInd) {
            ASSERT_DEBUG(modInd < ParamsType::kMaxNbModuli);
            return ParamsType::P[modInd];
        };

        template <ui32 modInd>
        static constexpr value_type inline getModulus() {
            static_assert(modInd < ParamsType::kMaxNbModuli);
            return ParamsType::P[modInd];
        };

        static constexpr ui32 inline getModulusRepresentationBitSize() {
            return ParamsType::kModulusRepresentationBitsize;
        };

        static constexpr value_type inline getPrimitiveMthRoot(const ui32 modInd) {
            ASSERT_DEBUG(modInd < ParamsType::kMaxNbModuli);
            return ParamsType::PrimitiveMthRoots[modInd];
        }

        static constexpr ui32 inline getMaxLogn(const ui32 modInd) {
            ASSERT_DEBUG(modInd < ParamsType::kMaxNbModuli);
            return ParamsType::getMaxLogn(modInd);
        }

        static constexpr ui32 inline getMaxNbModuli() { return ParamsType::kMaxNbModuli; }

        template <typename InputType>
        // static constexpr value_type inline mod(value_type x, ui32 modInd) {
        static constexpr value_type inline mod(InputType x, ui32 modInd) {
            const value_type p = ParamsType::P[modInd];
            const value_type pNewt = ParamsType::Pn[modInd];

            const greater_value_type q = 
                (((greater_value_type)pNewt) * ((greater_value_type)x >> shift)) 
                + ((greater_value_type)x << ParamsType::getS0(modInd));

            value_type r = (x - (q>>shift)*p) & shiftMask;
            STRICT_MOD(r, p);  // if (r >= p) r -= p;
            ASSERT_DEBUG(r == mod_slow(x, p));
            return r;
        };

        // NOTE: Google benchmark says this is slower than the regular function
        // template <ui32 modInd>
        // struct mod_op {
        //     static constexpr value_type p = ParamsType::P[modInd];
        //     static constexpr greater_value_type pNewt = (greater_value_type) ParamsType::Pn[modInd];
        //     static constexpr ui32 s0 = ParamsType::getS0(modInd);

        //     static constexpr inline value_type mod(const value_type x) {
        //         const greater_value_type q = 
        //             (pNewt * ((greater_value_type)x >> shift))
        //             + ((greater_value_type)x<<s0);
        //         // value_type r = (x - (q>>shift)*p) & (((greater_value_type)1<<shift)-1);
        //         value_type r = (x - (q>>shift)*p) & shiftMask;
        //         STRICT_MOD(r, p);  // if (r >= p) r -= p;
        //         ASSERT_DEBUG(r == mod_slow(x, p));
        //         return r;
        //     };
        // } __attribute__((aligned(32)));

        static constexpr value_type inline mod_add(const value_type x, const value_type y, const ui32 modInd) {
            const value_type modulus = getModulus(modInd);
            ASSERT_DEBUG((x<modulus)&&(y<modulus));
            value_type result = (x+y) - (modulus & static_cast<value_type>(
                -1*static_cast<signed_value_type>((x+y)>=modulus)
            ));
            ASSERT_DEBUG(result == mod_slow(x+y, modulus));
            return result;
        }

        static constexpr value_type inline mod_mul(const value_type x, const value_type y, const value_type p, const value_type pNewt, const ui32 modInd) {
            ASSERT_DEBUG((x<p)&&(y<p));
            const greater_value_type res = ((greater_value_type)x)*((greater_value_type)y);

            // newton reduction of res

            const greater_value_type q = 
                (((greater_value_type)pNewt) * (res >> shift)) 
                + (res << ParamsType::getS0(modInd));
            value_type r = (res - (q>>shift)*p) & shiftMask;
            STRICT_MOD(r, p);  // if (r >= p) r -= p;
            ASSERT_DEBUG(r == mod_mul_slow(x, y, p));
            return r;
        };

        static constexpr value_type inline mod_mul(const value_type x, const value_type y, const ui32 modInd) {
            ASSERT_DEBUG(modInd < ParamsType::kMaxNbModuli);
            const value_type p = ParamsType::P[modInd];
            const value_type pNewt = ParamsType::Pn[modInd];
            ASSERT_DEBUG((x<p)&&(y<p));
            return mod_mul(x, y, p, pNewt, modInd);
        };

        template <ui32 modInd>
        static constexpr value_type inline mod_mul(const value_type x, const value_type y) {
            constexpr value_type p = ParamsType::P[modInd];
            constexpr value_type pNewt = ParamsType::Pn[modInd];
            ASSERT_DEBUG((x<p)&&(y<p));
            return mod_mul(x, y, p, pNewt, modInd);
        };

        // NOTE: Google benchmark says this is slower than the regular function
        // template <ui32 modInd>
        // struct mod_mul_op {
        //     static constexpr value_type p = ParamsType::P[modInd];
        //     // static constexpr greater_value_type pNewt = (greater_value_type)ParamsType::Pn[modInd];
        //     static constexpr value_type pNewt = ParamsType::Pn[modInd];
        //     // static constexpr ui32 s0 = ParamsType::getS0(modInd);

        //     static constexpr inline value_type mod_mul(const value_type x, const value_type y) {
        //         ASSERT_DEBUG((x<p)&&(y<p));
        //         const greater_value_type res = ((greater_value_type)x)*((greater_value_type)y);
        //         // const greater_value_type q = ((greater_value_type)pNewt * (res >> shift)) + (res << s0);
        //         const greater_value_type q = ((greater_value_type)pNewt * (res >> shift)) + (res << ParamsType::getS0(modInd));
        //         value_type r = (res - (q>>shift)*p) & shiftMask;
        //             // (res - (q>>shift)*p) & (((greater_value_type)1<<shift)-1);
        //         STRICT_MOD(r, p);  // if (r >= p) r -= p;
        //         ASSERT_DEBUG(r == mod_mul_slow(x, y, p));
        //         return r;
        //     };
        // } __attribute__((aligned(32)));

        static constexpr value_type inline mod_mul_shoup(value_type x, value_type y, value_type yPrecomp, value_type p) {
            DEBUG_FUNC(return mod_mul_slow(x, y, p));
            ASSERT_DEBUG(x<p);
            ASSERT_DEBUG(y<p);
            // ASSERT_DEBUG(((T)yPrecomp == (T)((bigT)y << shift)/p));
            greater_value_type q = ((greater_value_type)x * yPrecomp) >> shift;
            value_type res = (value_type)((greater_value_type)x * y - q * p);
            // if (res >= p) res -= p;
            STRICT_MOD(res, p);
            ASSERT_DEBUG(res == mod_mul_slow(x, y, p));
            return res;
        };

        static constexpr inline value_type compute_shoup(const value_type in, const value_type modulus) {
            return ((greater_value_type)in << shift) / modulus;
        };
    };

    template <typename ParamsType, ui32 logn_in>
    class DCRT_Poly_Ring : public DCRT_Ring<ParamsType> {
    public:
        static constexpr ui32 logn = logn_in;
        static constexpr ui32 phim = 1<<logn;
    };


}  // namespace lbcrypto ends

#endif