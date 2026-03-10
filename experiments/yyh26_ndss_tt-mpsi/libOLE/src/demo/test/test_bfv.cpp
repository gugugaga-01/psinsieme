/*
    Unit tests for the BFV implementation
*/


#include "pke/bfv.h"
#include "utils/test.h"
#include "math/distributiongenerator.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCryptoNew;

template <typename BFV_Scheme_Type>
void test_sk_enc_dec(const BFV_Scheme_Type& scheme, const bool verbose = false, const ui32 trials = 100) {

    if (verbose) cout << "Calling keygen\n";
    auto kp = scheme.KeyGen();

    for (ui32 i = 0; i < trials; i++) {

        auto vals = scheme.encoding_context.generateRandomInput(false, 1);

        auto encodedCorrect = scheme.encoding_context.packed_encode(vals);

        if (verbose) cout << "Calling encrypt\n";

        auto ct = scheme.Encrypt(kp.sk, vals);

        if (verbose) cout << "Calling decrypt\n";

        // auto decEncoded = scheme.Decrypt_NoDecode(kp.sk, ct, verbose);
        auto toCheck = scheme.Decrypt(kp.sk, ct);

        // check_arr_eq(encodedCorrect, decEncoded, encodedCorrect.phim, "sk_enc dec encoding mismatch", true);

        if (!scheme.encoding_context.check_encoding_inputs_eq(vals, toCheck, 3))
            throw logic_error("sk_enc dec mismatch");
    }
    cout << "Secret Key Encrypt/Decrypt passed\n";
}

template <typename BFV_Scheme_Type>
void test_sk_enc_comp_dec(const BFV_Scheme_Type& scheme, const bool verbose = false, const ui32 trials = 100) {

    if (verbose) cout << "Calling keygen\n";
    auto kp = scheme.KeyGen();

    for (ui32 i = 0; i < trials; i++) {

        auto vals = scheme.encoding_context.generateRandomInput();

        // auto encoded = scheme.encoding_context.packed_encode(vals);

        if (verbose) cout << "Calling encrypt\n";

        auto ct = scheme.Encrypt(kp.sk, vals);

        auto ctSmall = scheme.CompressCiphertext(ct);

        if (verbose) cout << "Calling decrypt\n";

        // auto decEncoded = scheme.Decrypt_NoDecode(kp.sk, ctSmall, verbose);
        auto toCheck = scheme.Decrypt(kp.sk, ctSmall);

        // check_arr_eq(encoded.vals, decEncoded.vals, scheme.phim, "sk compressed encoded mismatch", true);

        if (verbose) cout << "Calling check_arr_eq\n";

        if (!scheme.encoding_context.check_encoding_inputs_eq(vals, toCheck, 3))
            throw logic_error("sk_enc compressed dec mismatch");
    }
    cout << "Secret Key Compressed Encrypt/Decrypt passed\n";
}


template <typename BFV_Scheme_Type>
void test_pk_enc_dec(const BFV_Scheme_Type& scheme, const ui32 trials = 100) {

    auto kp = scheme.KeyGen();

    auto kpSeeded = scheme.KeyGenSeeded();

    auto pkExpanded = kpSeeded.pkSeeded.expand();

    for (ui32 i = 0; i < trials; i++) {

        auto x = scheme.encoding_context.generateRandomInput();

        auto ct = scheme.Encrypt(kp.pk, x);

        auto toCheck = scheme.Decrypt(kp.sk, ct);

        if (!scheme.encoding_context.check_encoding_inputs_eq(x, toCheck))
            throw logic_error("pk_enc dec mismatch");
    }
    cout << "Public Key Encrypt/Decrypt passed\n";
}

template <typename BFV_Scheme_Type>
void test_pk_seeded_enc_dec(const BFV_Scheme_Type& scheme, const ui32 trials = 100) {

    auto kpSeeded = scheme.KeyGenSeeded();

    auto pkExpanded = kpSeeded.pkSeeded.expand();

    for (ui32 i = 0; i < trials; i++) {

        auto x = scheme.encoding_context.generateRandomInput();

        auto ct = scheme.Encrypt(pkExpanded, x);

        auto toCheck = scheme.Decrypt(kpSeeded.sk, ct);

        if (!scheme.encoding_context.check_encoding_inputs_eq(x, toCheck))
            throw logic_error("pk_enc seeded dec mismatch");
    }
    cout << "Seeded Public Key Encrypt/Decrypt passed\n";
}


template <typename BFV_Scheme_Type>
void test_easy_arithmetic(const BFV_Scheme_Type& scheme, const ui32 trials = 100) {

    auto kp = scheme.KeyGen();

    /** EvalAdd **/
    // using encoding_input_t = typename BFV_Scheme_Type::encoding_input_t;
    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        // encoding_input_t a; a.constructor(1);
        // encoding_input_t b; b.constructor(1);
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalAdd(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAdd simple mismatch");
    }
    cout << "EvalAdd simple test passed\n";

    // constexpr auto t = BFV_Scheme_Type::plaintextModulus;
    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        // encoding_input_t a; a.constructor(t-1);
        // encoding_input_t b; b.constructor(t-1);
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalAdd(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAdd less simple mismatch");
    }
    cout << "EvalAdd less simple test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalAdd(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAdd mismatch");
    }
    cout << "EvalAdd test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto pt = scheme.packed_encode(b);
        pt.ToEval(scheme.ntt_context);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalAddPlain(ct1, pt);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAddPlain mismatch");
    }
    cout << "EvalAddPlain test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalAddPlain(ct1, b);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAddPlain + scaling mismatch");
    }
    cout << "EvalAddPlain + scaling test passed\n";

    /** EvalMultPlain **/

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_prod(a, b);
        auto ct1 = scheme.Encrypt(kp.sk, a);
        auto pt = scheme.packed_encode(b);
        pt.ToEval(scheme.ntt_context);
        auto ctRes = scheme.EvalMultPlain(ct1, pt);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalMultPlain mismatch");
    }
    cout << "EvalMultPlain test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_prod(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalMultPlain(ct1, b);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalMultPlain + encoding mismatch");
    }
    cout << "EvalMultPlain + encoding test passed\n";

    /**  EvalSub  **/
    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_diff(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalSub(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalSub mismatch");
    }
    cout << "EvalSub test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_diff(a, b);
        auto pt = scheme.packed_encode(b);
        pt.ToEval(scheme.ntt_context);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalSubPlain(ct1, pt);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalSubPlain mismatch");
    }
    cout << "EvalSubPlain test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_diff(b, a);
        auto pt = scheme.packed_encode(b);
        pt.ToEval(scheme.ntt_context);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalSubPlain(pt, ct1);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalSubPlain (rev) mismatch");
    }
    cout << "EvalSubPlain (rev) test passed\n";

}

template <typename BFV_Scheme_Type>
void test_dcrt_compression(const BFV_Scheme_Type& scheme, const bool verbose = false, const ui32 trials = 100) {

    using DCRTPoly = typename BFV_Scheme_Type::DCRTPoly_;
    using RingType = typename BFV_Scheme_Type::RingType;
    using ptPoly = typename BFV_Scheme_Type::ptPoly;
    using plaintext_type = typename BFV_Scheme_Type::plaintext_type;

    auto kp = scheme.KeyGen();
    for (ui32 i = 0; i < trials; i++) {
        // auto vals = scheme.encoding_context.generateRandomInput(false, 1);
        auto vals = scheme.encoding_context.generateRandomInput();

        auto pt_arr = scheme.encoding_context.packed_encode(vals);
        DCRTPoly pt(pt_arr, true);

        pt *= scheme.deltas;

        auto toUnwrap = scheme.dcrt_params.compressDCRTPoly(pt);

        ptPoly toDecode;
        for (i = 0; i < scheme.phim; i++) {
            fl128 floatDec = (fl128)scheme.plaintextModulus * (fl128)toUnwrap[i] / (fl128)RingType::getModulus(0);
            plaintext_type resVal = (plaintext_type)floatDec;
            if (floatDec - resVal >= 0.5) resVal++;
            toDecode[i] = resVal;
            if (toDecode[i] == scheme.plaintextModulus) toDecode[i] = 0;
        }

        auto toCheck = scheme.encoding_context.packed_decode(toDecode);

        if (!scheme.encoding_context.check_encoding_inputs_eq(vals, toCheck, 3))
            throw logic_error("dcrt_compression mismatch");
    }
    cout << "dcrt_compression passed\n";
}

void runStandardBFVTests() {
    CHECK_DEBUG_VERBOSE;
    cout << "Runnng BFV tests...\n";

    typedef ui64 T;
    constexpr ui32 numLimbs = 3;
    // constexpr ui32 numExtLimbs = 4;

    constexpr ui32 logn = 4;
    // constexpr ui32 phim = 1<<logn;
    constexpr ui32 p = 557057;

    typedef DCRT_Poly_Ring<params<ui32>, logn> SmallPlaintextRing;
    typedef EncodingContext<SmallPlaintextRing, p> small_encoding_context_t;
    // typedef EncodingContext<ui64, logn, p> small_encoding_context_t;
    typedef DCRT_Ring<params<T>> CiphertextIntegerRing;
    typedef DCRT_Params<CiphertextIntegerRing, numLimbs, numLimbs+1, p> dcrt_params_t;

    BFV_DCRT<small_encoding_context_t, dcrt_params_t> smallScheme;

    const ui32 trials = 5;
    const bool verbose = false;

    test_sk_enc_dec(smallScheme, verbose, trials);
    test_sk_enc_comp_dec(smallScheme, verbose, trials);
    test_pk_enc_dec(smallScheme, trials);
    test_pk_seeded_enc_dec(smallScheme, trials);

    // return;  // DEBUG

    constexpr ui32 normLogn = 11;
    // constexpr ui32 normLogn = 8;
    typedef EncodingContext<DCRT_Poly_Ring<params<ui32>, normLogn>, p> norm_encoding_context_t;
    BFV_DCRT<norm_encoding_context_t, dcrt_params_t> scheme;

    test_sk_enc_dec(scheme);
    test_sk_enc_comp_dec(scheme, verbose);
    test_pk_enc_dec(scheme);
    test_easy_arithmetic(scheme);

    constexpr ui32 bigLogn = 15;
    // constexpr ui32 bigP = 786433;
    constexpr ui32 bigP = 5767169;

    typedef EncodingContext<DCRT_Poly_Ring<params<ui32>, bigLogn>, bigP> big_encoding_context_t;
    typedef DCRT_Params<CiphertextIntegerRing, numLimbs, numLimbs+1, bigP> big_dcrt_params_t;
    BFV_DCRT<big_encoding_context_t, big_dcrt_params_t> bigScheme;


    static_assert( sizeof(bigScheme) < 1000, "bigScheme too large");

    cout << "\n\nRunning big BFV tests...\n";

    test_sk_enc_dec(bigScheme, false, 5);
    // test_sk_enc_comp_dec(scheme, false, 5);
    test_pk_enc_dec(bigScheme, 5);
    test_easy_arithmetic(bigScheme, 5);
}

void runFastTwoLimbReductionTest() {
    CHECK_DEBUG_VERBOSE;
    cout << "Runnng Fast two-limb reduction BFV tests...\n";

    // typedef ui64 T;
    // constexpr ui32 numLimbs = 3;
    // constexpr ui32 numExtLimbs = 4;

    constexpr ui32 logn = 4;
    // constexpr ui32 phim = 1<<logn;
    constexpr ui32 p = 557057;

    typedef DCRT_Poly_Ring<params<ui32>, logn> SmallPlaintextRing;
    typedef EncodingContext<SmallPlaintextRing, p> small_encoding_context_t;
    // typedef EncodingContext<ui64, logn, p> small_encoding_context_t;
    typedef DCRT_Ring<fast_two_limb_reduction_params> CiphertextIntegerRing;
    typedef DCRT_Fast_Two_Limb_Reduction_Params<CiphertextIntegerRing, p> dcrt_params_t;

    BFV_DCRT<small_encoding_context_t, dcrt_params_t> smallScheme;

    const ui32 trials = 5;
    const bool verbose = false;

    test_dcrt_compression(smallScheme, verbose, trials);
    test_sk_enc_dec(smallScheme, verbose, trials);
    test_sk_enc_comp_dec(smallScheme, verbose, trials);
    test_pk_enc_dec(smallScheme, trials);
    test_pk_seeded_enc_dec(smallScheme, trials);
};

void runFastThreeLimbReductionTest() {
    CHECK_DEBUG_VERBOSE;
    cout << "Runnng Fast three-limb reduction BFV tests...\n";

    // typedef ui64 T;
    // constexpr ui32 numLimbs = 3;
    // constexpr ui32 numExtLimbs = 4;

    constexpr ui32 logn = 4;
    // constexpr ui32 phim = 1<<logn;
    // constexpr ui32 p = 557057;
    constexpr ui64 p = fast_three_limb_reduction_params::P[0];

    typedef DCRT_Poly_Ring<fast_three_limb_reduction_params, logn> SmallPlaintextRing;
    typedef EncodingContext<SmallPlaintextRing, p> small_encoding_context_t;
    // typedef EncodingContext<ui64, logn, p> small_encoding_context_t;
    typedef DCRT_Ring<fast_three_limb_reduction_params> CiphertextIntegerRing;
    typedef DCRT_Fast_Three_Limb_Reduction_Params<CiphertextIntegerRing, p> dcrt_params_t;

    BFV_DCRT<small_encoding_context_t, dcrt_params_t> smallScheme;

    const ui32 trials = 5;
    const bool verbose = false;

    test_dcrt_compression(smallScheme, verbose, trials);
    test_sk_enc_dec(smallScheme, verbose, trials);
    test_sk_enc_comp_dec(smallScheme, verbose, trials);
    test_pk_enc_dec(smallScheme, trials);
    test_pk_seeded_enc_dec(smallScheme, trials);
};

void runFastFourLimbReductionTest() {
    CHECK_DEBUG_VERBOSE;
    cout << "Runnng Fast four-limb reduction BFV tests...\n";

    // typedef ui64 T;
    // constexpr ui32 numLimbs = 3;
    // constexpr ui32 numExtLimbs = 4;

    constexpr ui32 logn = 4;
    // constexpr ui32 phim = 1<<logn;
    constexpr ui32 p = 557057;

    typedef DCRT_Poly_Ring<params<ui32>, logn> SmallPlaintextRing;
    typedef EncodingContext<SmallPlaintextRing, p> small_encoding_context_t;

    typedef DCRT_Ring<fast_four_limb_reduction_params> CiphertextIntegerRing;
    typedef DCRT_Fast_Four_Limb_Reduction_Params<CiphertextIntegerRing, p> dcrt_params_t;

    BFV_DCRT<small_encoding_context_t, dcrt_params_t> smallScheme;

    const ui32 trials = 5;
    const bool verbose = false;

    test_dcrt_compression(smallScheme, verbose, trials);
    test_sk_enc_dec(smallScheme, verbose, trials);
    test_sk_enc_comp_dec(smallScheme, verbose, trials);
    test_pk_enc_dec(smallScheme, trials);
    test_pk_seeded_enc_dec(smallScheme, trials);
};

void runFast31BitPrimeThreeLimbReductionTest() {
    CHECK_DEBUG_VERBOSE;
    cout << "Runnng Fast three-limb reduction BFV tests...\n";

    typedef ui64 ptType;

    constexpr ui32 logn = 4;
    // constexpr ui32 phim = 1<<logn;
    constexpr ui32 p = 4294475777;

    typedef DCRT_Poly_Ring<params<ptType>, logn> SmallPlaintextRing;
    typedef EncodingContext<SmallPlaintextRing, p> small_encoding_context_t;
    // typedef EncodingContext<ui64, logn, p> small_encoding_context_t;
    typedef DCRT_Ring<fast_31_bit_prime_three_limb_compression_params> CiphertextIntegerRing;
    typedef DCRT_Fast_Three_Limb_Reduction_Params<CiphertextIntegerRing, p> dcrt_params_t;

    BFV_DCRT<small_encoding_context_t, dcrt_params_t> smallScheme;

    const ui32 trials = 5;
    const bool verbose = false;

    test_sk_enc_dec(smallScheme, verbose, trials);
    test_easy_arithmetic(smallScheme, trials);
    test_sk_enc_comp_dec(smallScheme, verbose, trials);
    test_pk_enc_dec(smallScheme, trials);
    test_pk_seeded_enc_dec(smallScheme, trials);
};

template <typename BFV_Scheme_Type>
void test_easy_arithmetic_polys(const BFV_Scheme_Type& scheme, const ui32 trials = 100) {

    auto kp = scheme.KeyGen();

    /** EvalAdd **/
    // using encoding_input_t = typename BFV_Scheme_Type::encoding_input_t;
    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        // encoding_input_t a; a.constructor(1);
        // encoding_input_t b; b.constructor(1);
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalAdd(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAdd simple mismatch");
    }
    cout << "EvalAdd simple test passed\n";

    // constexpr auto t = BFV_Scheme_Type::plaintextModulus;
    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        // encoding_input_t a; a.constructor(t-1);
        // encoding_input_t b; b.constructor(t-1);
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalAdd(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAdd less simple mismatch");
    }
    cout << "EvalAdd less simple test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ct2 = scheme.Encrypt(kp.pk, b);
        auto ctRes = scheme.EvalAdd(ct1, ct2);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAdd mismatch");
    }
    cout << "EvalAdd test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto pt = scheme.packed_encode(b);
        pt.ToEval(scheme.ntt_context);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalAddPlain(ct1, pt);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAddPlain mismatch");
    }
    cout << "EvalAddPlain test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto correct = scheme.encoding_context.enc_input_sum(a, b);
        auto ct1 = scheme.Encrypt(kp.pk, a);
        auto ctRes = scheme.EvalAddPlain(ct1, b);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalAddPlain + scaling mismatch");
    }
    cout << "EvalAddPlain + scaling test passed\n";

    /** EvalMultPlain **/

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomScalar();
        auto correct = scheme.encoding_context.enc_input_prod(a, b);
        auto ct1 = scheme.Encrypt(kp.sk, a);
        auto b_input = scheme.encoding_context.packed_encode(b);
        auto pt = scheme.packed_encode(b_input);
        pt.ToEval(scheme.ntt_context);
        auto ctRes = scheme.EvalMultPlain(ct1, pt);
        auto toCheck = scheme.Decrypt(kp.sk, ctRes);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalMultPlain mismatch");
    }
    cout << "EvalMultPlain test passed\n";

    for (ui32 i = 0; i < trials; i++) {
        auto a = scheme.encoding_context.generateRandomInput();
        auto b = scheme.encoding_context.generateRandomInput();
        auto x = scheme.encoding_context.generateRandomScalar();
        auto correct = scheme.encoding_context.enc_input_sum(scheme.encoding_context.enc_input_prod(a, x), b);

        auto pt_x = scheme.encoding_context.packed_encode(x);

        auto ct = scheme.Encrypt(kp.sk, pt_x);

        auto ctRes = scheme.EvalAddPlain(scheme.EvalMultPlain(ct, a), b);
        auto ctComp = scheme.CompressCiphertext(ctRes);
        auto toCheck = scheme.Decrypt(kp.sk, ctComp);
        if (!scheme.encoding_context.check_encoding_inputs_eq(correct, toCheck))
            throw logic_error("EvalOLE mismatch");
    }
    cout << "EvalOLE test passed\n";

}

void runBFVPolyEncoding() {
    CHECK_DEBUG_VERBOSE;
    cout << "Runnng BFV tests...\n";

    typedef ui64 T;
    constexpr ui32 numLimbs = 3;

    constexpr ui32 logn = 4;
    constexpr ui32 p = 557057;

    typedef DCRT_Poly_Ring<params<ui32>, logn> SmallPlaintextRing;
    typedef NullEncodingContext<SmallPlaintextRing, p> small_encoding_context_t;
    typedef DCRT_Ring<params<T>> CiphertextIntegerRing;
    typedef DCRT_Params<CiphertextIntegerRing, numLimbs, 0, p> dcrt_params_t;

    BFV_DCRT<small_encoding_context_t, dcrt_params_t> smallScheme;

    const ui32 trials = 5;
    const bool verbose = false;

    test_sk_enc_dec(smallScheme, verbose, trials);
    test_sk_enc_comp_dec(smallScheme, verbose, trials);
    test_pk_enc_dec(smallScheme, trials);
    test_easy_arithmetic_polys(smallScheme, trials);
}


int main() {

    // runFast31BitPrimeThreeLimbReductionTest();
    // runFastThreeLimbReductionTest();
    // runFastTwoLimbReductionTest();
    // runFastFourLimbReductionTest();
    runStandardBFVTests();
    // runBFVPolyEncoding();
}
