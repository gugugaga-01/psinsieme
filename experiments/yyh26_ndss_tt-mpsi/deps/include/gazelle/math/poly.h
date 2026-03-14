/*
    Defines polynomial types

    Author: Leo de Castro
    Date: 03/12/2019
*/

#ifndef LBCRYPTO_MATH_POLY_H
#define LBCRYPTO_MATH_POLY_H


#include <boost/type_traits/is_base_of.hpp>

#include "distributiongenerator.h"
#include "transfrm.h"
#include "utils/test.h"

namespace lbcrypto {

    //
    // Matrix
    //

    template <typename T>
    struct Matrix {
        // std::vector<std::shared_ptr<T>> data;
        std::vector<T*> data;
        const size_t innerSize;
        bool init = false;

        Matrix() {};  // For vector initialization
        Matrix(size_t outerSize, size_t innerSize_in) : innerSize(innerSize_in), init(true) {
            data.reserve(outerSize);
            for (ui32 i = 0; i < outerSize; i++) {
                alignas(32) auto ptr = new T[innerSize];
                data.push_back(ptr);
                // data.push_back(std::shared_ptr<T>(ptr));
                // data.push_back(std::shared_ptr<T>(new T[innerSize]));
                // data.push_back(new T[innerSize]);
            }
        };

        ~Matrix() {
            for (ui32 i = 0; i < data.size(); i++)
                delete[] data[i];
                // delete[] data[i].get();
        };

        inline void zero() {
            for (ui32 i = 0; i < data.size(); i++)
                for (ui32 j = 0; j < innerSize; j++)
                    data[i][j] = 0;
        }

        inline void arrFill(const T * vec) {
            for (ui32 i = 0; i < data.size(); i++)
                for (ui32 j = 0; j < innerSize; j++)
                    data[i][j] = vec[j];
        }

        inline T * operator[](const size_t i) {return data[i];};
        inline T * operator[](const size_t i) const {return data[i];};
        inline size_t size() const {return data.size();};
    };

    template <typename T>
    Matrix<T> PowersOfBase(const T * vec, const ui32 size, const ui32 baseBits, const ui64 q);

    template <typename T>
    Matrix<T> BaseDecompose(const T * vec, const ui32 size, const ui32 window_size, const ui32 num_windows);

    template <typename T>
    void automorph(T * result, const T * input, const ui32 * indices, ui32 size, ui32 rot);

    template <typename T>
    void automorph_pt(T * result, const T * input, ui32 phim, ui32 rot);


    //
    // poly
    //

    template<typename T, ui32 size>
    struct Array {
        T vals[size] __attribute__((aligned(32)));
        inline T& operator[](const size_t i) { ASSERT_DEBUG(i<size); return vals[i]; };
        inline T operator[](const size_t i) const { ASSERT_DEBUG(i<size); return vals[i]; };
        inline operator T * () { return &(vals[0]); };
        inline operator T * () const { return &(vals[0]); };
    }  __attribute__((packed));

    class poly_base {};

    template <typename RingType_in, ui32 modInd_in = 0>
    class poly : poly_base {
    public:
        typedef RingType_in RingType;

        using value_type = typename RingType::value_type;
        static constexpr ui32 modInd = modInd_in;
        static constexpr ui32 phim = RingType::phim;

        // using mod_functor = typename RingType::template mod_op<modInd>;
        // using mod_mul_functor = typename RingType::template mod_mul_op<modInd>;

        alignas(32) value_type * vals = new value_type[phim];

        ~poly() {
            delete[] vals;
        }

        inline void constructor(const value_type v = 0) {
            // std::fill(std::begin(vals), std::end(vals), v);
            for (ui32 i = 0; i < phim; i++)
                vals[i] = v;
        }

        poly(const value_type v = 0) {
            constructor(v);
        };

        poly(const poly<RingType>& o) {
            ASSERT_DEBUG(o.phim == phim);
            std::copy(o.vals, o.vals+phim, vals);
        };

        template <typename InputType>
        poly(const InputType a, ui32 size=phim) {
            ASSERT_DEBUG(size<=phim);
            // constructor();
            for (ui32 i = 0; i < size; i++)
                vals[i] = a[i];
            for (ui32 i = size; i < phim; i++)
                vals[i] = 0;
        };

        inline value_type& operator[](const size_t i) {
            ASSERT_DEBUG(i < phim);
            return vals[i];
        };

        inline value_type operator[](const size_t i) const {
            ASSERT_DEBUG(i < phim);
            return vals[i];
        };

        inline void random(const value_type modulus) {
            get_dug_array(vals, phim, modulus);
        };

        inline void zeros() { constructor(); };
        inline void ones() { constructor(1); };
        inline void repeat_const(value_type v) { constructor(v); };

        inline std::vector<poly<RingType>> bitDecompose(const ui32 bitWidth) const {
            std::vector<poly<RingType>> result(bitWidth);
            for (ui32 i = 0; i < phim; i++) {
                value_type currVal = vals[i];
                for (ui32 b = 0; b < bitWidth; b++) {
                    result[b][i] = currVal & 1;
                    ASSERT_DEBUG(result[b][i] == 0 || result[b][i] == 1);
                    currVal >>= 1;
                }
                ASSERT_DEBUG(currVal == 0);
            }
            return result;
        };

        bool isBinary() const {
            for (ui32 i = 0; i < phim; i++)
                if (vals[i] != 0 && vals[i] != 1) return false;
            return true;
        };

        /** NTT **/

        inline void ToCoeff(const NTT_Context_Base<RingType> * const context) {
            context->ftt_inv(vals);
        };

        inline void ToEval(const NTT_Context_Base<RingType> * const context) {
            context->ftt_fwd(vals);
        };

        /** Operators **/

        inline bool operator==(const poly<RingType, modInd>& right) const {
            for (ui32 j = 0; j < phim; j++) {
                if (vals[j] != right.vals[j])
                    return false;
            }
            return true;
        }

        inline bool operator!=(const poly<RingType, modInd>& right) const {
            return !(*this == right);
        }

        inline poly<RingType, modInd>& operator=(const poly<RingType, modInd>& o) {
            std::copy(o.vals, o.vals+phim, vals);
            return *this;
        };

        inline void operator+=(const poly<RingType, modInd>& o) {
            for (ui32 i = 0; i < phim; i++)
                vals[i] = RingType::mod_add(vals[i], o[i], modInd);
        };

        inline void operator*=(const ui64 d) {
            ASSERT_DEBUG(d < RingType::template getModulus<modInd>());
            for (ui32 i = 0; i < phim; i++)
                vals[i] = RingType::mod_mul(vals[i], d, modInd);
                // vals[i] = mod_mul_functor::mod_mul(vals[i], d);
        };

        operator value_type * () { return &(vals[0]); };
        operator value_type * () const { return &(vals[0]); };

        std::string to_string() const {
            return arr_to_string(vals, phim);
        };

        void negate(const value_type modulus) {
            for (ui32 i = 0; i < phim; i++) {
                ASSERT_DEBUG(modulus > vals[i]);
                vals[i] = modulus - vals[i];
            }
        };

        void negate() { negate(RingType::template getModulus<modInd>()); };

    };

    /** Basic Arithmetic **/

    template <typename RingType, ui32 modInd=0>
    inline poly<RingType, modInd> operator+(const poly<RingType, modInd>& a, const poly<RingType, modInd>& b) {
        // using mod_functor = typename RingType::template mod_op<modInd>;
        poly<RingType, modInd> result;
        constexpr ui32 phim = RingType::phim;
        for (ui32 i = 0; i < phim; i++)
            result[i] = RingType::mod_add(a[i], b[i], modInd);
        return result;
    };

    template <typename RingType, ui32 modInd=0>
    inline poly<RingType, modInd> operator-(const poly<RingType, modInd>& a, const poly<RingType, modInd>& b) {
        // using mod_functor = typename RingType::template mod_op<modInd>;
        poly<RingType, modInd> result;
        constexpr ui32 phim = RingType::phim;
        for (ui32 i = 0; i < phim; i++)
            result[i] = RingType::mod_add(a[i], RingType::template getModulus<modInd>() - b[i], modInd);
        return result;
    };

    template <typename RingType, ui32 modInd=0>
    inline poly<RingType, modInd> operator*(const poly<RingType, modInd>& a, const poly<RingType, modInd>& b) {
        // using mod_mul_functor = typename RingType::template mod_mul_op<modInd>;
        poly<RingType, modInd> result;
        constexpr ui32 phim = RingType::phim;
        for (ui32 i = 0; i < phim; i++)
            result[i] = RingType::mod_mul(a[i], b[i], modInd);
            // result[i] = mod_mul_functor::mod_mul(a[i], b[i]);
        return result;
    };


    //
    // AlignedVec
    //

    template <typename T, ui32 logn_in>
    struct AlignedVec {

        typedef T value_type;

        static constexpr ui32 logn = logn_in; 
        static constexpr ui32 phim = 1<<logn;

        alignas(32) value_type * vals = new value_type[phim];

        ~AlignedVec() {
            delete[] vals;
        }

        inline void constructor(const value_type v = 0) {
            for (ui32 i = 0; i < phim; i++)
                vals[i] = v;
        };

        AlignedVec(const bool init) {
            ASSERT_DEBUG(!init);
        };

        AlignedVec(const value_type v = 0) {
            constructor(v);
        };

        AlignedVec(const AlignedVec<T, logn>& o) {
            std::copy(o.vals, o.vals+phim, vals);
        };

        template <typename InputType>
        AlignedVec(const InputType a, const ui32 size) {
            ASSERT_DEBUG(size <= phim);
            for (ui32 i = 0; i < size; i++)
                vals[i] = a[i];
            for (ui32 i = size; i < phim; i++)
                vals[i] = 0;
        };

        template <typename InType>
        AlignedVec(const std::vector<InType>& a) {
            const ui32 size = a.size();
            ASSERT_DEBUG(size <= phim);
            for (ui32 i = 0; i < size; i++)
                vals[i] = a[i];
            for (ui32 i = size; i < phim; i++)
                vals[i] = 0;
        };

        inline value_type& operator[](const size_t i) {
            ASSERT_DEBUG(i < phim);
            return vals[i];
        };

        inline value_type operator[](const size_t i) const {
            ASSERT_DEBUG(i < phim);
            return vals[i];
        };

        inline AlignedVec<T, logn>& operator=(const AlignedVec<T, logn>& o) {
            for (ui32 i = 0; i < phim; i++)
                vals[i] = o.vals[i];
            return *this;
        }

        inline bool operator==(const AlignedVec<T, logn>& o) const {
            for (ui32 i = 0; i < phim; i++)
                if (vals[i] != o.vals[i]) return false;
            return true;
        }

        inline bool operator!=(const AlignedVec<T, logn>& o) const {
            for (ui32 i = 0; i < phim; i++)
                if (vals[i] != o.vals[i]) return true;
            return false;
        }

        operator value_type * () { return &(vals[0]); };
        operator value_type * () const { return &(vals[0]); };

        string to_string() const {
            return arr_to_string(vals, phim);
        };
    };

    template <typename T, ui32 logn>
    inline AlignedVec<T, logn> operator+(const AlignedVec<T, logn>& a, const AlignedVec<T, logn>& b) {
        AlignedVec<T, logn> result;
        constexpr ui32 phim = 1<<logn;
        #pragma clang loop vectorize(enable) interleave(enable)
        for (ui32 i = 0; i < phim; i++)
            result[i] = a[i] + b[i];
        return result;
    };

    template <typename T, ui32 logn>
    inline AlignedVec<T, logn> operator-(const AlignedVec<T, logn>& a, const AlignedVec<T, logn>& b) {
        AlignedVec<T, logn> result;
        constexpr ui32 phim = 1<<logn;
        #pragma clang loop vectorize(enable) interleave(enable)
        for (ui32 i = 0; i < phim; i++)
            result[i] = a[i] - b[i];
        return result;
    }; 
    
    template <typename T, ui32 logn>
    inline AlignedVec<T, logn> operator*(const AlignedVec<T, logn>& a, const AlignedVec<T, logn>& b) {
        AlignedVec<T, logn> result;
        constexpr ui32 phim = 1<<logn;
        #pragma clang loop vectorize(enable) interleave(enable)
        for (ui32 i = 0; i < phim; i++)
            result[i] = a[i] * b[i];
        return result;
    };



    //
    // DCRT
    //

    template<typename T, ui32 xSize, ui32 ySize>
    struct Array2d {
        std::shared_ptr<Array<Array<T, ySize>, xSize>> vals = allocate_shared_ptr<Array<Array<T, ySize>, xSize>>();

        inline T* operator[](const size_t i) { ASSERT_DEBUG(i<xSize); return (T*)(*vals)[i]; };
        inline T* operator[](const size_t i) const { ASSERT_DEBUG(i<xSize); return (T*)(*vals)[i]; };

        inline Array2d<T, xSize, ySize>& operator=(const Array2d<T, xSize, ySize>& o) {
            for (ui32 x = 0; x < xSize; x++)
                for (ui32 y = 0; y < ySize; y++)
                    vals[x][y] = o.vals[x][y];
            return *this;
        };

        inline bool operator==(const Array2d<T, xSize, ySize>& o) {
            for (ui32 x = 0; x < xSize; x++)
                for (ui32 y = 0; y < ySize; y++)
                    if (vals[x][y] != o.vals[x][y]) return false;
            return true;
        };

    } __attribute__((packed));

    class DCRTPolyBase {};

    template <typename RingType_in, ui32 numLimbs_in>
    class DCRTPoly : DCRTPolyBase {
    public:
        typedef RingType_in RingType;

        static constexpr ui32 logn = RingType::logn;
        static constexpr ui32 phim = 1<<logn;
        static constexpr ui32 numLimbs = numLimbs_in;

        typedef typename RingType::value_type value_type;
        typedef typename RingType::signed_value_type signed_value_type;
        typedef typename RingType::greater_value_type greater_value_type;
        // using my_type = typename DCRTPoly<RingType, numLimbs>;

        typedef DCRTPoly<RingType, numLimbs-1> ReducedType;

        // value_type vals[numLimbs][phim] __attribute__((aligned(32)));
        Array2d<value_type, numLimbs, phim> vals;

        // TODO: Add startLimb for easy multiplication
        // const ui32 startLimb;

        // ~DCRTPoly() {
            // free(vals);
        // }

        static ui32 getNumBytes() {
            if (is_same<value_type, ui64>::value)
                return 8*phim*numLimbs;
            else if (is_same<value_type, ui32>::value)
                return 4*phim*numLimbs;
            else
                throw std::logic_error("Cannot process size for this type");
        };

        template<class Archive>
        void serialize(Archive & ar, const unsigned int version) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    ar & vals[i][j];
        }

        template<typename InputType>
        static bool checkReduced(const InputType a[], const ui32 size=phim) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < size; j++)
                    if (a[j] >= RingType::getModulus(i))
                        return false;
            return true;
        }

        bool checkSelfReduced() const {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    if (vals[i][j] >= RingType::getModulus(i))
                        return false;
            return true;
        }

        inline void constructor(const value_type v=0, const bool init = false) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = v;
        }

        // DCRTPoly() { constructor(); };
        DCRTPoly() { };

        DCRTPoly(const DCRTPoly<RingType, numLimbs>& o) {
            constructor();
            for (ui32 i=0; i<o.numLimbs; i++)
                for (ui32 j=0; j<o.phim; j++)
                    vals[i][j] = o.vals[i][j];
                // std::copy(o.vals[i], o.vals[i]+phim, vals[i]);
        };

        template <ui32 otherLimbs>
        DCRTPoly(const DCRTPoly<RingType, otherLimbs>& o) {
            constructor();
            ASSERT_DEBUG(o.phim == phim);
            // ASSERT_DEBUG(o.numLimbs <= numLimbs);
            if (o.numLimbs <= numLimbs) {
                assert(o.numLimbs == 1);
                // for (ui32 i=0; i<o.numLimbs; i++)
                for (ui32 i=0; i<numLimbs; i++)
                    for (ui32 j=0; j<o.phim; j++)
                        vals[i][j] = RingType::mod(o.vals[0][j], i);
            } else {
                for (ui32 i=0; i<numLimbs; i++)
                    for (ui32 j=0; j<phim; j++)
                        vals[i][j] = o.vals[i][j];
            }
                // std::copy(o.vals[i], o.vals[i]+phim, vals[i]);
        };

        template <typename InputType>
        DCRTPoly(const InputType a[], const ui32 size=phim) {
            constructor();
            ASSERT_DEBUG(size <= phim);
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < size; j++)
                    vals[i][j] = RingType::mod((value_type)a[j], i);
                    // vals[i][j] = mod((value_type)a[j], i);
        };

        // DCRTPoly(const poly<RingType>& o) : DCRTPoly(o.vals, true) {};
        DCRTPoly(const poly<RingType>& o, const bool noMod=false) : DCRTPoly(o.vals, noMod) {};
        // DCRTPoly(const poly<RingType>& o) : DCRTPoly(o.vals) {};

        template<typename InputType>
        DCRTPoly(const InputType a[], const bool noMod, const ui32 size=phim) {
            ASSERT_DEBUG(noMod);
            ASSERT_DEBUG(checkReduced(a));
            // constructor();
            ASSERT_DEBUG(size <= phim);
            for (ui32 i = 0; i < numLimbs; i++)
                std::copy(a, a+phim, vals[i]);
        };

        DCRTPoly(const osuCryptoNew::block seed) {
            // if (phim < 8)
                for (ui32 i = 0; i < numLimbs; i++)
                    get_dug_array_from_seed(vals[i], phim, seed, RingType::getModulus(i));
            // else
                // for (ui32 i = 0; i < numLimbs; i++)
                    // get_dug_array_from_seed_parallel(vals[i], phim, seed, RingType::getModulus(i));
        };

        DCRTPoly(const osuCryptoNew::PRNG prng) {
            for (ui32 i = 0; i < numLimbs; i++)
                get_dug_array_from_prng(vals[i], phim, prng, RingType::getModulus(i));
        };

        DCRTPoly(const uvbi bigVals) {
            constructor();
            ASSERT_DEBUG(bigVals.size() <= phim);
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < bigVals.size(); j++)
                    vals[i][j] = (bigVals[j] % ubi(RingType::getModulus(i))).toUnsignedLong();
        };

        DCRTPoly(const Matrix<value_type>& inputMat) {
            constructor();
            ASSERT_DEBUG(inputMat.size() == numLimbs);
            ASSERT_DEBUG(inputMat.innerSize <= phim);
            for (ui32 i = 0; i < inputMat.size(); i++)
                for (ui32 j = 0; j < inputMat.innerSize; j++)
                    vals[i][j] = mod(inputMat[i][j], i);
        };

        /** Data access and generators **/

        inline value_type const * operator[](const size_t i) const {
            ASSERT_DEBUG(i<numLimbs);
            return vals[i];
        };

        inline value_type * operator[](const size_t i) {
            ASSERT_DEBUG(i<numLimbs);
            return vals[i];
        };

        inline void random() {
            for (ui32 i = 0; i < numLimbs; i++)
                get_dug_array(vals[i], phim, RingType::getModulus(i));
        };

        inline void ones() { constructor(1); };
        inline void zeros() { constructor(); };
        inline void repeat_const(value_type c) { constructor(c); };

        /** Shoup Multiplication **/
        DCRTPoly<RingType, numLimbs> compute_shoup() const {
            DCRTPoly<RingType, numLimbs> result;
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    result[i][j] = ((greater_value_type)vals[i][j] << RingType::getModulusRepresentationBitSize()) / RingType::getModulus(i);
            return result;
        };

        /** NTT **/

        inline void ToCoeff(NTT_Context_Base<RingType>** contexts) {
            for (ui32 i = 0; i < numLimbs; i++)
                contexts[i]->ftt_inv(vals[i]);
        }

        inline void ToEval(NTT_Context_Base<RingType>** contexts) {
            for (ui32 i = 0; i < numLimbs; i++)
                contexts[i]->ftt_fwd(vals[i]);
        }

        /** Arithmetic **/

        // NOTE: Assumes the values are already mod-reduced
        inline void negate() {
            ASSERT_DEBUG(checkSelfReduced());
            for (ui32 i = 0; i < numLimbs; i++) {
                for (ui32 j = 0; j < phim; j++)
                    if (vals[i][j] != 0) vals[i][j] = RingType::getModulus(i) - vals[i][j];
            }
        };

        inline void operator*=(const DCRTPoly<RingType, numLimbs>& right) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = RingType::mod_mul(vals[i][j], right[i][j], i);
        };

        inline void operator*=(const value_type right) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = RingType::mod_mul(vals[i][j], right, i);
        };

        inline void operator*=(const std::vector<value_type> right) {
            ASSERT_DEBUG(right.size() == numLimbs);
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = RingType::mod_mul(vals[i][j], right[i], i);
        };

        inline void operator+=(const DCRTPoly<RingType, numLimbs>& right) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = RingType::mod_add(vals[i][j], right[i][j], i);
        };

        inline void operator-=(const DCRTPoly<RingType, numLimbs>& right) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = RingType::mod_add(vals[i][j], RingType::getModulus(i) - right[i][j], i);
        };

        inline bool operator==(const DCRTPoly<RingType, numLimbs>& right) const {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    if (vals[i][j] != right.vals[i][j])
                        return false;
            return true;
        }

        inline bool operator!=(const DCRTPoly<RingType, numLimbs>& right) const {
            return !(*this == right);
        }

        inline DCRTPoly<RingType, numLimbs>& operator=(const DCRTPoly<RingType, numLimbs>& o) {
            for (ui32 i = 0; i < numLimbs; i++)
                for (ui32 j = 0; j < phim; j++)
                    vals[i][j] = o.vals[i][j];
            return *this;
        }

        /** Decomp and Powers **/

        std::vector<DCRTPoly<RingType, numLimbs>> CRTPowersOfBase(const ui32 baseBits) const {
            std::vector<DCRTPoly<RingType, numLimbs>> result;
            for (ui32 i = 0; i < numLimbs; i++) {
                Matrix<value_type> powElems = PowersOfBase(vals[i], phim, baseBits, RingType::getModulus(i));
                for (ui32 k = 0; k < powElems.size(); k++) {
                    DCRTPoly<RingType, numLimbs> filtered;
                    std::copy(powElems[k], powElems[k] + phim, filtered.vals[i]);
                    result.push_back(filtered);
                }
            }
            return result;
        };

        std::vector<DCRTPoly<RingType, numLimbs>> CRTBaseDecompose(const ui32 baseBits) const {
            ui32 resultSize = 0;
            for (ui32 i = 0; i < numLimbs; i++)
                resultSize += 1 + floor(log2(RingType::getModulus(i)))/baseBits;

            // std::vector<DCRTPoly<RingType, numLimbs>> result(resultSize);
            std::vector<DCRTPoly<RingType, numLimbs>> result; result.reserve(resultSize);
            // ui32 currOffset = 0;
            for (ui32 i = 0; i < numLimbs; i++) {
                ui32 num_windows = 1 + floor(log2(RingType::getModulus(i)))/baseBits;
                Matrix<value_type> decomposed = BaseDecompose(vals[i], phim, baseBits, num_windows);
                ASSERT_DEBUG(decomposed.size() == num_windows);
                for (ui32 j = 0; j < num_windows; j++) {
                    // DCRTPoly<RingType, numLimbs> currPoly(decomposed[j]);
                    // result[j + currOffset] = currPoly;
                    result.push_back(DCRTPoly<RingType, numLimbs>(decomposed[j]));
                }
                // currOffset += num_windows;
            }
            return result;
        };

        /** Printing **/

        inline std::string to_string() const {
            std::string output = "{";
            for (ui32 i = 0; i<numLimbs; i++) {
                output += arr_to_string(vals[i], phim);
                output += (i==numLimbs-1) ? "}" : ", ";
            }
            return output;
        };

        /** Automorphism **/

        inline DCRTPoly<RingType, numLimbs> Automorph(const ui32 * indices, const ui32 rot) const {
            DCRTPoly<RingType, numLimbs> result;
            for (ui32 i = 0; i < numLimbs; i++)
                automorph(result.vals[i], vals[i], indices, phim, rot);
            return result;
        };

        inline void conjugate() {
            for (ui32 limbInd = 0; limbInd < numLimbs; limbInd++)
                for (ui32 i = 0; i < phim; i++)
                    std::swap(vals[limbInd][i], vals[limbInd][phim-1-i]);
        };
    };


    /**  Basic DCRTPoly Arithmetic  **/

    template <typename DCRTPolyType>
    inline DCRTPolyType operator*(const DCRTPolyType& left, const DCRTPolyType& right) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;
        DCRTPolyType result;
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod_mul(left[i][j], right[i][j], i);
        return result;
    };

    template <typename DCRTPolyType>
    inline DCRTPolyType operator*(const DCRTPolyType& left, const vector<typename DCRTPolyType::value_type> right) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;
        ASSERT_DEBUG(right.size() == numLimbs);
        DCRTPolyType result;
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod_mul(left[i][j], right[i], i);
        return result;
    };

    template <typename DCRTPolyType, 
        typename = std::enable_if_t<
            boost::is_base_of<DCRTPolyBase, DCRTPolyType>::value>>
    inline DCRTPolyType operator+(const DCRTPolyType& left, const DCRTPolyType& right) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;
        ASSERT_DEBUG(left.checkSelfReduced());
        ASSERT_DEBUG(right.checkSelfReduced());
        DCRTPolyType result;
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod_add(left[i][j], right[i][j], i);                
        return result;
    };


    template <typename DCRTPolyType, 
        typename = std::enable_if_t<
            boost::is_base_of<DCRTPolyBase, DCRTPolyType>::value>
    >
    inline DCRTPolyType operator-(const DCRTPolyType& left, const DCRTPolyType& right) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;
        DCRTPolyType result;
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod_add(left[i][j], RingType::getModulus(i) - right[i][j], i);
        return result;
    };


    template <typename DCRTPolyType, typename OperandType>
    inline DCRTPolyType mod_mul_shoup(const DCRTPolyType& left, const OperandType& right, const OperandType& rightShoup) {
        using RingType = typename DCRTPolyType::RingType;
        ASSERT_DEBUG(OperandType::numLimbs >= DCRTPolyType::numLimbs);
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;
        DCRTPolyType result;
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod_mul_shoup(left[i][j], right[i][j], rightShoup[i][j], RingType::getModulus(i));
        return result;
    }

    template <typename DCRTPolyType>
    inline void mod_mul_shoup_sub(DCRTPolyType& result, const DCRTPolyType& left, const DCRTPolyType& right, const DCRTPolyType& rightShoup) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;        
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod_add(
                    result.vals[i][j],
                    RingType::getModulus(i) 
                        - RingType::mod_mul_shoup(
                            left[i][j], right[i][j], rightShoup[i][j], RingType::getModulus(i)),
                    i
                );
    }

    template <typename DCRTPolyType>
    inline DCRTPolyType threeSum(const DCRTPolyType& left, const DCRTPolyType& middle, const DCRTPolyType& right) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;        
        DCRTPolyType result;
        for (ui32 i = 0; i < numLimbs; i++)
            for (ui32 j = 0; j < phim; j++)
                result.vals[i][j] = RingType::mod(left.vals[i][j] + middle.vals[i][j] + right.vals[i][j], i);
        return result;
    }


    template <typename DCRTPolyType>
    inline void recombMult(DCRTPolyType& result, const std::vector<Matrix<typename DCRTPolyType::value_type>>& a, const std::vector<Matrix<typename DCRTPolyType::value_type>>& b) {
        using RingType = typename DCRTPolyType::RingType;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = RingType::phim;
        ASSERT_DEBUG(a.size() == b.size());
        for (ui32 digit = 0; digit < a.size(); digit++) {
            ASSERT_DEBUG(a[digit].size() == b[digit].size());
            ASSERT_DEBUG(a[digit].size() == numLimbs);
            ASSERT_DEBUG(a[digit].innerSize == b[digit].innerSize);
            ASSERT_DEBUG(a[digit].innerSize == phim);
            for (ui32 limb = 0; limb < numLimbs; limb++)
                for (ui32 i = 0; i < phim; i++)
                    // TODO: Add shoup
                    result.vals[limb][i] =
                        mod(result.vals[limb][i] +
                            mod_mul(a[digit][limb][i], b[digit][limb][i], limb),
                        limb);
        }
    }


    template <typename DCRTPolyType>
    inline void recombMult(DCRTPolyType& result, const std::vector<DCRTPolyType>& a, const std::vector<DCRTPolyType>& b) {
        // constexpr ui32 phim = 1<<logn;
        ASSERT_DEBUG(a.size() == b.size());
        for (ui32 i = 0; i < a.size(); i++) {
            result = result + (a[i]*b[i]);
        }
    }

    template <typename DCRTPolyType>
    inline DCRTPolyType conjugate(const DCRTPolyType& input) {
        DCRTPolyType result;
        constexpr ui32 numLimbs = DCRTPolyType::numLimbs;
        constexpr ui32 phim = DCRTPolyType::phim;
        for (ui32 limbInd = 0; limbInd < numLimbs; limbInd++)
            for (ui32 i = 0; i < phim; i++)
                result[limbInd][i] = input[limbInd][phim-1-i];
        return result;
    }

}  // namespace lbcrypto ends

#endif
