#include <iostream>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <complex>

#include "backend.h"

#ifndef LBCRYPTO_TEST_H
#define LBCRYPTO_TEST_H

using namespace std;

namespace lbcrypto {

sv64 to_signed(uv64 v, ui64 p);


std::string to_string(ubi x);
std::string to_string_cmplx(const complex<double> x);

std::string ui128_to_string(ui128 x);

std::string to_string(ui128 x);


static bool test_h_init = false;
inline double get_random_real() {
    if (!test_h_init) { srand(time(0)); test_h_init=true; }
    return static_cast <float> (rand()) / static_cast <float> (RAND_MAX);
};

inline complex<double> get_random_complex() {
    double v1 = get_random_real();
    double v2 = get_random_real();
    return complex<double>(v1, v2);
}

template <typename T>
std::string arr_to_string(const T a, const size_t size) {
    std::stringstream buffer;
    buffer << "{";
    for(ui32 i=0; i<size; i++){
        std::string end = (i!=size-1) ? ", " : "}";
        buffer << std::to_string(a[i]) << end;
    }

    return buffer.str();

    /*
    std::string str = "{";
    for(ui32 i=0; i<size; i++){
        std::string end = (i!=size-1) ? ", " : "}";
        str += std::to_string(a[i]) + end;
    }

    return str;
    */
}

template<typename T>
std::string array_2d_to_string(const T a, const size_t xDim, const size_t yDim) {
    std::string str = "{";
    for(ui32 i=0; i<xDim; i++){
        std::string end = (i!=xDim-1) ? ", " : "}";
        str += arr_to_string(a[i], yDim) + end;
    }

    return str;
}

std::string vec_to_str(std::vector<ubi> v);

template<typename IntType>
std::string vec_to_str(std::vector<IntType> v){
    std::string str;
    for(ui32 i=0; i<v.size(); i++){
        // str += std::to_string(v[i]) + " ";
        str += std::to_string(v[i]) + " ";
    }

    return str;
}

std::string vec_to_str_cmplx(const std::vector<complex<double>>& v, const bool imag=false);
std::string mat_to_str_cmplx(const std::vector<std::vector<complex<double>>>& m, const bool imag=true);


std::string mat_to_str_double(const std::vector<std::vector<double>>& m);

template <typename T1, typename T2>
void check_arr_eq(const T1 a1, const T2 a2, const size_t size, const std::string& what = "check_arr_eq failed", const bool verbose = false, const bool fineGrain = false) {
    for (ui32 i = 0; i < size; i++) {
        // if (a1[i] != a2[i]) {
        if (fabs(a1[i] - a2[i]) > 1e-5) {
            if (verbose) {
                if (fineGrain) {
                    std::cout << "Index " << i << std::endl;
                    std::cout << a1[i] << " != " << a2[i] << std::endl;
                } // else {
                    std::cout << arr_to_string(a1, size) << std::endl;
                    std::cout << arr_to_string(a2, size) << std::endl;
                // }
            }
            throw std::logic_error(what);
        }
    }
}

template <typename T1, typename T2>
void check_arr_approx_eq(const T1 a1, const T2 a2, const size_t size, const std::string& what = "check_arr_approx_eq failed", const bool verbose = false, const bool fineGrain = false, const double minThresh = 1e-11) {
    for (ui32 i = 0; i < size; i++) {
        double thresh = std::max(0.01*std::min(std::abs(a1[i]), std::abs(a2[i])), minThresh);
        if (fabs(a1[i] - a2[i]) > thresh) {
            if (verbose) {
                if (fineGrain) {
                    std::cout << "Index " << i << std::endl;
                    std::cout << a1[i] << " != " << a2[i] << std::endl;
                    std::cout << "thresh = " << thresh << std::endl;
                }
                std::cout << arr_to_string(a1, size) << std::endl;
                std::cout << arr_to_string(a2, size) << std::endl;
            }
            throw std::logic_error(what);
        }
    }
}

// void check_compex_arr_eq(const complex<double> * a1, const complex<double> * a2, const size_t size, const std::string& what = "check_arr_eq failed", const bool verbose = false, const bool fineGrain = false) {
//     for (ui32 i = 0; i < size; i++) {
//         // if (a1[i] != a2[i]) {
//         if (fabs(a1[i] - a2[i]) < 0.001) {
//             if (verbose) {
//                 if (fineGrain) {
//                     std::cout << "Index " << i << std::endl;
//                     std::cout << a1[i] << " != " << a2[i] << std::endl;
//                 } // else {
//                     std::cout << arr_to_string(a1, size) << std::endl;
//                     std::cout << arr_to_string(a2, size) << std::endl;
//                 // }
//             }
//             throw std::logic_error(what);
//         }
//     }
// }

template<typename IntType>
void check_vec_eq(std::vector<IntType> v1, std::vector<IntType> v2,
        const std::string& what = "", const bool verbose = false){
    if(v1 != v2){
        if (verbose) std::cout << vec_to_str(v1) << std::endl;
        if (verbose) std::cout << vec_to_str(v2) << std::endl;
        throw std::logic_error(what);
    }

    return;
}

template<typename IntType>
void check_mat_eq(
        std::vector<std::vector<IntType>> m1,
        std::vector<std::vector<IntType>> m2,
        const std::string& what=""){
    if(m1.size() != m2.size()){
        std::cout << "Sizes: " << m1.size() << " " << m1.size() << std::endl;
        throw std::logic_error(what);
        // return m2.size();
    } else {
        for(ui32 n=0; n<m1.size(); n++){
            if(m1[n] != m2[n]){
                std::cout << "Mismatch on row: " << n << std::endl;
                std::cout << vec_to_str(m1[n]) << std::endl;
                std::cout << vec_to_str(m2[n]) << std::endl;
                //return n;
                throw std::logic_error(what);
            }
        }
    }
}

template<typename T1, typename T2>
void check_mat_eq(T1& m1, T2& m2, ui32 height, ui32 width, const std::string& what="Matrix mismatch!") {
    for (ui32 i = 0; i < height; i++)
        for (ui32 j = 0; j < width; j++)
            if (m1[i][j] != m2[i][j]) {
                std::cout << m1[i][j] << " != " << m2[i][j] << std::endl;
                throw std::logic_error(what);
            }
}

}  // namespace lbcrypto ends

#endif
