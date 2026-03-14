/*
    transfrm.h

    Ciphertext-level NTTS
    Author: Leo de Castro
*/

#ifndef LBCRYPTO_MATH_TRANSFRM_H
#define LBCRYPTO_MATH_TRANSFRM_H


#include <chrono>
#include <complex>
#include <time.h>
#include <map>
#include <fstream>
#include <thread>
#include <iostream>

#include "ring.h"
#include "nbtheory.h"
#include "bit_twiddle.h"
#include "utils/test.h"

using namespace std;

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

    template <size_t degree>
    struct permut_compute {
      typedef ui32 value_type;

      // value_type * data_ = new value_type[degree];
      constexpr permut_compute() : data_()
      {
        for (value_type i = 0; i < degree; ++i) {
          value_type ii = i;
          value_type r = 0;

          for (value_type h = 1; h < degree; h=h<<1)
          {
            r = (r << 1) | (ii & 1);
            ii >>= 1;
          }

          data_[i] = r;
        }
      };
      value_type data_[degree];

      inline constexpr value_type operator()(size_t i) const {
        ASSERT_DEBUG(i < degree);
        return data_[i];
      };

      // ~permut_compute() { delete[] data_; };
    };

    //
    // NTT
    //

    // Loads roots of unity in David Harvey's order
    // template <typename T, ui32 phim>
    // inline void prep_wtab(typename T * wtab, T * wtabshoup, T w, T p) {
    template <typename RingType, ui32 phim>
    constexpr inline void prep_wtab(
      typename RingType::value_type * wtab, 
      typename RingType::value_type * wtabshoup, 
      typename RingType::value_type w, 
      typename RingType::value_type p) 
    {
      using bigT = typename RingType::greater_value_type;

      unsigned K = phim;
      ui32 count = 0;
      while (K >= 2)
      {
        ui128 wi = 1;     // w^i
        // ui64 wi = 1;
        for (size_t i = 0; i < K/2; i++)
        {
          *wtab++ = wi;
          count++;
          *wtabshoup++ = ((bigT) wi << RingType::shift) / p;
          wi = mod_mul_slow(static_cast<typename RingType::value_type>(wi), w, p);

        }
        w = mod_mul_slow(w, w, p);
        K /= 2;
      }
    }

    template <typename RingType, ui32 modInd>
    struct NTT_Params {

        using value_type = typename RingType::value_type;
        using greater_value_type = typename RingType::greater_value_type;

        static constexpr value_type modulus = RingType::getModulus(modInd);
        static constexpr ui32 phim = RingType::phim;
        static constexpr ui32 logn = RingType::logn;

        static constexpr value_type phi = mod_exp(
            RingType::getPrimitiveMthRoot(modInd), ((value_type)1)<<(RingType::getMaxLogn(modInd) - logn), modulus
          );
        static constexpr value_type phiInv = mod_inv(phi, modulus);
        static constexpr value_type omega = mod_mul_slow(phi, phi, modulus);
        static constexpr value_type omegaInv = mod_inv(omega, modulus);

        static constexpr value_type phimInv = mod_inv(phim, modulus);

        alignas(32) value_type * phiRootsOfUnity = new value_type[2*phim];
        value_type * phiRootsOfUnityShoup = phiRootsOfUnity + phim;

        alignas(32) value_type * omegaRootsOfUnity = new  value_type[2*phim];
        value_type * omegaRootsOfUnityShoup = omegaRootsOfUnity + phim;

        alignas(32) value_type * phiInvRootsOfUnity = new value_type[2*phim];
        value_type * phiInvRootsOfUnityShoup = phiInvRootsOfUnity + phim;

        alignas(32) value_type * omegaInvRootsOfUnity = new value_type[2*phim];
        value_type * omegaInvRootsOfUnityShoup = omegaInvRootsOfUnity + phim;

        static constexpr inline value_type compute_shoup(const value_type in) {
            return ((greater_value_type)in << RingType::shift) / modulus;
        };

        constexpr NTT_Params() {
            CHECK_DEBUG;
            ASSERT_DEBUG(mod_exp(phi, (ui64)phim<<1, modulus) == 1);
            ASSERT_DEBUG(mod_exp(phi, (ui64)phim, modulus) == modulus-1);
            ASSERT_DEBUG(mod_exp(omega, (ui64)phim, modulus) == 1);
            ASSERT_DEBUG(phiInv == mod_inv(phi, modulus));
            ASSERT_DEBUG(omega == mod_mul_slow(phi, phi, modulus));
            ASSERT_DEBUG(omegaInv == mod_inv(omega, modulus));
            ASSERT_DEBUG((modulus % (1<<(logn+1)))==1);

            for (ui32 i = 0; i < 2*phim; i++) {
                phiRootsOfUnity[i] = 0;
                omegaRootsOfUnity[i] = 0;
                phiInvRootsOfUnity[i] = 0;
                omegaInvRootsOfUnity[i] = 0;
            }

            value_type x = 1;
            for (ui32 i = 0; i < phim; i++) {
                phiRootsOfUnity[i] = x;
                x = RingType::mod_mul(x, phi, modInd);
            }
            for (ui32 i = 0; i < phim; i++)
                phiRootsOfUnityShoup[i] = compute_shoup(phiRootsOfUnity[i]);

            x = 1;
            for (ui32 i = 0; i < phim; i++) {
                phiInvRootsOfUnity[i] = RingType::mod_mul(x, phimInv, modInd);
                x = RingType::mod_mul(x, phiInv, modInd);
            }
            for (ui32 i = 0; i < phim; i++)
                phiInvRootsOfUnityShoup[i] = compute_shoup(phiInvRootsOfUnity[i]);

            prep_wtab<RingType, phim>(omegaRootsOfUnity, omegaRootsOfUnityShoup, omega, modulus);
            prep_wtab<RingType, phim>(omegaInvRootsOfUnity, omegaInvRootsOfUnityShoup, omegaInv, modulus);
        };

        ~NTT_Params() {
            delete[] phiRootsOfUnity;
            delete[] omegaRootsOfUnity;
            delete[] phiInvRootsOfUnity;
            delete[] omegaInvRootsOfUnity;
        };

    };

    template <typename RingType>
    class NTT_Context_Base {
    public:
        using value_type = typename RingType::value_type;
        virtual bool ftt_fwd(value_type * x) const = 0;
        virtual bool ftt_inv(value_type * x) const = 0;
        virtual ~NTT_Context_Base() {};
    };

    template <typename RingType, ui32 modInd>
    class NTT_Context : public NTT_Context_Base<RingType> {
    public:
        using value_type = typename RingType::value_type;
        using greater_value_type = typename RingType::greater_value_type;

        static constexpr value_type modulus = RingType::template getModulus<modInd>();
        static constexpr ui32 logn = RingType::logn;
        static constexpr ui32 phim = RingType::phim;

        static const NTT_Params<RingType, modInd> ntt_params;

        static constexpr size_t J = logn-2;
        static constexpr size_t M = 1<<J;

        static const std::shared_ptr<permut_compute<RingType::phim>> perm;

        ~NTT_Context() {};

        static constexpr inline void ntt_loop_body(value_type* x0, value_type* x1, value_type const* winvtab, value_type const* wtab) {
            value_type u0 = *x0;
            value_type u1 = *x1;

            value_type t0 = u0 + u1;
            t0 -= ((t0 >= 2*modulus) ? (2*modulus) : 0);

            value_type t1 = u0 - u1 + 2*modulus;

            value_type q = ((greater_value_type) t1 * (*winvtab)) >> RingType::getModulusRepresentationBitSize();
            value_type t2 = t1 * (*wtab) - q * modulus;

            *x0 = t0;
            *x1 = t2;
        };

        static inline void run(value_type* x, const value_type* &wtab, const value_type* &winvtab) {
            for (size_t w = 0; w < J; w++) {
                const size_t M = 1 << w;
                const size_t N = phim >> w;
                for (size_t r = 0; r < M; r++) {
                    for (size_t i = 0; i < N/2; i += 2) {
                        ntt_loop_body(&x[N * r + i + 0], &x[N * r + i + 0 + N/2], &winvtab[i + 0], &wtab[i + 0]);
                        ntt_loop_body(&x[N * r + i + 1], &x[N * r + i + 1 + N/2], &winvtab[i + 1], &wtab[i + 1]);
                    }
                }
                wtab += N / 2;
                winvtab += N / 2;
            }
        };

        static inline void ntt_fwd(value_type* x, value_type const * wtab, value_type const * winvtab) {

            value_type * x_orig = x;

            run(x, wtab, winvtab);

            typedef typename std::make_signed<value_type>::type signed_value_type;
            // last two layers
            for (size_t r = 0; r < M; r++, x += 4)
            {
              value_type u0 = x[0];
              value_type u1 = x[1];
              value_type u2 = x[2];
              value_type u3 = x[3];

              value_type v0 = u0 + u2;
              v0 -= (v0 >= 2*modulus) ? (2*modulus) : 0;
              value_type v2 = u0 - u2;
              v2 += ((signed_value_type) v2 < 0) ? (2*modulus) : 0;

              value_type v1 = u1 + u3;
              v1 -= (v1 >= 2*modulus) ? (2*modulus) : 0;
              value_type t = u1 - u3 + 2*modulus;

              value_type q = ((greater_value_type)t * winvtab[1]) >> RingType::getModulusRepresentationBitSize();
              value_type v3 = t * wtab[1] - q * modulus;

              value_type z0 = v0 + v1;
              z0 -= (z0 >= 2*modulus) ? (2*modulus) : 0;
              value_type z1 = v0 - v1;
              z1 += ((signed_value_type) z1 < 0) ? (2*modulus) : 0;

              value_type z2 = v2 + v3;
              z2 -= (z2 >= 2*modulus) ? (2*modulus) : 0;
              value_type z3 = v2 - v3;
              z3 += ((signed_value_type) z3 < 0) ? (2*modulus) : 0;

              x[0] = z0;
              x[1] = z1;
              x[2] = z2;
              x[3] = z3;
            }

            for (size_t i = 0; i < phim; i++) {
              STRICT_MOD(x_orig[i], modulus);
              // x_orig[i]-= ((x_orig[i]>=modulus)? modulus : 0);
              ASSERT_DEBUG(x_orig[i] < modulus);
            }

        };

        bool ftt_fwd(value_type * x) const {
            for (ui32 i = 0; i < phim; i++)
                x[i] = RingType::mod_mul_shoup(x[i], ntt_params.phiRootsOfUnity[i], ntt_params.phiRootsOfUnityShoup[i], modulus);

            ntt_fwd(x, ntt_params.omegaRootsOfUnity, ntt_params.omegaRootsOfUnityShoup);

            alignas(32) value_type * y = new value_type[phim];
            compute_permutation(y, x);
            std::copy(y, y+phim, x);
            delete[] y;

            return true;
        };


        static inline void compute_permutation(value_type* y, value_type const* x) {
            for (size_t i = 0; i < phim; ++i)
                y[i] = x[(*perm)(i)];
        };

        bool ftt_inv(value_type * x) const {

          alignas(32) value_type * y = new value_type[phim];

          ntt_fwd(x, ntt_params.omegaInvRootsOfUnity, ntt_params.omegaInvRootsOfUnityShoup);

          compute_permutation(y, x);
          std::copy(y, y+phim, x);


          for (ui32 i = 0; i < phim; i++)
            x[i] = RingType::mod_mul_shoup(x[i], ntt_params.phiInvRootsOfUnity[i], ntt_params.phiInvRootsOfUnityShoup[i], modulus);

          delete[] y;

          return true;
        };

    };

    template<typename RingType, ui32 modInd>
    const NTT_Params<RingType, modInd> NTT_Context<RingType, modInd>::ntt_params;

    template<typename RingType, ui32 modInd>
    const std::shared_ptr<permut_compute<RingType::phim>> NTT_Context<RingType, modInd>::perm = std::shared_ptr<permut_compute<RingType::phim>>(new permut_compute<RingType::phim>());

    //
    // Mult-limb NTT_Context
    //

    template <typename RingType, ui32 numLimbs_in>
    class MultiLimb_NTT_Context {
    public:
        static constexpr ui32 numLimbs = numLimbs_in;

        NTT_Context_Base<RingType>* ntt_contexts[numLimbs];
        NTT_Context_Base<RingType>** ntt_context;

        template<class none = void>
        constexpr inline void nttInit() { return; };  // Base case for shrinking list initialization

        template<ui32 i, ui32 ... j>
        constexpr inline void nttInit() {
            ntt_contexts[i] = new NTT_Context<RingType, i>();
            nttInit<j...>();
        };

        template<size_t J, size_t ... I>
        constexpr inline void nttInitStart(std::index_sequence<J, I...>) {
            nttInit<J, I...>();
        };

        template<ui32 N, typename Indices = std::make_index_sequence<N>>
        constexpr inline void nttInit_new() {
            nttInitStart(Indices{});
        };

        constexpr MultiLimb_NTT_Context() {
            nttInit_new<numLimbs>();
            ntt_context = &(ntt_contexts[0]);
        };

        ~MultiLimb_NTT_Context() {
            for (ui32 i = 0; i < numLimbs; i++)
                delete ntt_contexts[i];
        };

        operator NTT_Context_Base<RingType> **() const { return ntt_context; };
    };

} // namespace lbcrypto ends

#endif
