/*
Unit tests for number theory operations
*/

#include "utils/test.h"
#include "math/distributiongenerator.h"
#include "math/nbtheory.h"
#include "math/ring.h"

using namespace lbcrypto;

template <typename RingType>
void test_mod_mul(ui32 phim = 1000) {
    // ui32 modInd = 1;
    using value_type = typename RingType::value_type;

    for (ui32 modInd = 0; modInd < RingType::getMaxNbModuli(); modInd++) {
        value_type p = RingType::getModulus(modInd);
        std::vector<value_type> a_vec = get_dug_vector(phim, p);
        std::vector<value_type> b_vec = get_dug_vector(phim, p);
        std::vector<value_type> correct(phim);
        for (ui32 i=0; i<phim; i++)
            correct[i] = mod_mul_slow(a_vec[i], b_vec[i], p);

        std::vector<value_type> toCheck(phim);
        for (ui32 i = 0; i < phim; i++)
            toCheck[i] = RingType::mod_mul(a_vec[i], b_vec[i], modInd);

        if (correct != toCheck) {
            std::cout << "modInd = " << modInd << std::endl;
            std::cout << "a = " << vec_to_str(a_vec) << std::endl;
            std::cout << "b = " << vec_to_str(b_vec) << std::endl;
            std::cout << "correct = " << vec_to_str(correct) << std::endl;
            std::cout << "toCheck = " << vec_to_str(toCheck) << std::endl;
            assert(1 == 0);
            // check_vec_eq(correct, toCheck, "regular mod mul not working");
        }
    }
    std::cout << "Test basic mod_mul w/ our primes passed\n";
}


ui64 computeNewtonInverse(ui64 p) {
    // ui128 beta_sq = ((ui128)1 << 127) + (((ui128)1 << 127) - 1);
    // ui64 v = (ui64)(beta_sq/(ui128)p - ((ui128)1<<64));
    ubi beta_sq = ubi(1) << 128;
    ui64 v = ( (beta_sq/ubi(p)) % (ubi(1) << 64) ).toUnsignedLong();
    return v;
}

template <typename RingType>
ui64 inline mod_mul(ui64 x, ui64 y, ui64 p, ui64 pNewt, ui32 modInd) {
    ASSERT_DEBUG((x<p)&&(y<p));
    using value_type = typename RingType::value_type;
    using greater_value_type = typename RingType::greater_value_type;

    const greater_value_type res = ((greater_value_type)x)*((greater_value_type)y);
    const greater_value_type q = 
        (((greater_value_type)pNewt) * (res >> RingType::shift)) 
        + (res << RingType::ParamsType::getS0(modInd));
    value_type r = (res - (q>>RingType::shift)*p) & RingType::shiftMask;
        // (res - (q>>shift)*p) & (((greater_value_type)1<<shift)-1);
    STRICT_MOD(r, p);  // if (r >= p) r -= p;
    ASSERT_DEBUG(r == mod_mul_slow(x, y, p));
    return r;
};

// Test NFL techniques with 59 bit primes
template <typename RingType>
void test_mod_mul_crt_primes(const ui32 phim = 100, const ui32 modInd = 0) {
    // ui64 p = 4611686018326724609ULL;
    // ui64 p = 1152921504499937281ULL;
    // ui64 p = 36028797018652673;
    // ui64 pNewt = computeNewtonInverse(p);
    // ui64 pNewt = 81604116480;

    // ui64 p = 36028796997599233ULL;
    ui64 p = RingType::getModulus(modInd);
    ui64 pNewt = computeNewtonInverse(p);
    std::cout << "modInd = " << modInd << std::endl;
    std::cout << "p = " << p << std::endl;
    std::cout << "pNewt = " << pNewt << std::endl;
 
    // uv64 a_vec = get_dug_vector(phim, p);
    // uv64 b_vec = get_dug_vector(phim, p);
    uv64 a_vec = {p-1};
    uv64 b_vec = {p-1};
    uv64 correct(phim);
    for (ui32 i=0; i<phim; i++)
        correct[i] = mod_mul_slow(a_vec[i], b_vec[i], p);

    uv64 toCheck(phim);
    for (ui32 i = 0; i < phim; i++)
        toCheck[i] = mod_mul<RingType>(a_vec[i], b_vec[i], p, pNewt, modInd);

    if (correct != toCheck) {
        std::cout << "a = " << vec_to_str(a_vec) << std::endl;
        std::cout << "b = " << vec_to_str(b_vec) << std::endl;
        std::cout << "correct = " << vec_to_str(correct) << std::endl;
        std::cout << "toCheck = " << vec_to_str(toCheck) << std::endl;
        assert(1 == 0);
        // check_vec_eq(correct, toCheck, "regular mod mul not working");
    }

    std::cout << "Custon pNewt test passed\n";
}


template <typename RingType>
void test_mod_mul_shoup(const ui32 phim = 1000) {
    using value_type = typename RingType::value_type;
    for (ui32 modInd = 0; modInd < RingType::getMaxNbModuli(); modInd++) {
        value_type p = RingType::getModulus(modInd);
        std::vector<value_type> a_vec = get_dug_vector(phim, p);
        std::vector<value_type> b_vec = get_dug_vector(phim, p);
        std::vector<value_type> correct(phim);
        for (ui32 i=0; i<phim; i++)
            correct[i] = mod_mul_slow(a_vec[i], b_vec[i], p);

        using bigT = typename RingType::greater_value_type;

        std::vector<value_type> precomputed(phim);
        for (ui32 i = 0; i < phim; i++)
            precomputed[i] = (((bigT)b_vec[i]) << RingType::getModulusRepresentationBitSize())/p;

        std::vector<value_type> toCheck(phim);
        for (ui32 i = 0; i < phim; i++)
            toCheck[i] = RingType::mod_mul_shoup(a_vec[i], b_vec[i], precomputed[i], p);

        if (correct != toCheck) {
            std::cout << "modInd = " << modInd << std::endl;
            std::cout << "a = " << vec_to_str(a_vec) << std::endl;
            std::cout << "b = " << vec_to_str(b_vec) << std::endl;
            std::cout << "correct = " << vec_to_str(correct) << std::endl;
            std::cout << "toCheck = " << vec_to_str(toCheck) << std::endl;
            assert(1 == 0);
            // check_vec_eq(correct, toCheck, "regular mod mul not working");
        }
    }
    std::cout << "Test basic mod_mul_shoup w/ our primes passed\n";
}

void test_basic_ops() {
    test_mod_mul<DCRT_Ring<params<ui64>>>();
    test_mod_mul<DCRT_Ring<params<ui32>>>();
    // test_mod_mul_crt_primes();
    test_mod_mul_shoup<DCRT_Ring<params<ui64>>>();
    test_mod_mul_shoup<DCRT_Ring<params<ui32>>>();


    // test_mod_mul_crt_primes<DCRT_Ring<params<ui64>>>(1);
    // std::cout << "Starting fast reduction tests\n";
    // test_mod_mul_crt_primes<DCRT_Ring<fast_two_limb_reduction_params>>(100, 0);
    // test_mod_mul_crt_primes<DCRT_Ring<fast_two_limb_reduction_params>>(100, 1);

    // test_mod_mul<DCRT_Ring<fast_two_limb_reduction_params>>();
    // test_mod_mul_shoup<DCRT_Ring<fast_two_limb_reduction_params>>();

    // test_mod_mul_crt_primes<DCRT_Ring<fast_31_bit_prime_three_limb_compression_params>>(100, 0);
    // test_mod_mul_crt_primes<DCRT_Ring<fast_31_bit_prime_three_limb_compression_params>>(100, 1);

    test_mod_mul<DCRT_Ring<fast_31_bit_prime_three_limb_compression_params>>();
    test_mod_mul_shoup<DCRT_Ring<fast_31_bit_prime_three_limb_compression_params>>();

    // test_mod_mul<DCRT_Ring<approx_params<55>>>();
    // test_mod_mul_shoup<DCRT_Ring<approx_params<55>>>();

    std::cout << "Basic ops tests passed\n";
}

int main() {
    test_basic_ops();
}
