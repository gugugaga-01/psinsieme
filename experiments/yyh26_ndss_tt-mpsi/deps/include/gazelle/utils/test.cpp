
#include "utils/test.h"

using namespace std;

namespace lbcrypto {

std::string to_string(ubi x) { return bigUnsignedToString(x); }

std::string to_string_cmplx(complex<double> x) { 
    return "(" + std::to_string(x.real()) + ", " + std::to_string(x.imag()) + ")"; 
}

std::string ui128_to_string(ui128 x) {
    std::string result;
    while (x > 0) {
        uint32_t dig = x % 10;
        result = std::to_string(dig) + result;
        x /= 10;
    }
    return result;
}

std::string to_string(ui128 x) { return ui128_to_string(x); }


std::string vec_to_str_cmplx(const std::vector<complex<double>>& v, const bool imag) {
    std::string str;
    for(ui32 i=0; i<v.size(); i++){
        if (imag)
            str += to_string_cmplx(v[i]) + " ";
        else
            str += std::to_string(v[i].real()) + " ";
    }

    return str;
};

std::string mat_to_str_cmplx(const std::vector<std::vector<complex<double>>>& m, const bool imag){
    std::string str;
    for(ui32 j=0; j<m.size(); j++){
        str += vec_to_str_cmplx(m[j], imag);
        // for(ui32 i=0; i<m[0].size(); i++){
        //     if (imag)
        //         str += to_string_cmplx(m[j][i]) + " ";
        //     else
        //         str += std::to_string(m[j][i].real()) + " ";
        // }
        str += "\n";
    }
    return str;
}

std::string vec_to_str(std::vector<ubi> v){
    std::string str;
    for(ui32 i=0; i<v.size(); i++){
        // str += std::to_string(v[i]) + " ";
        str += to_string(v[i]) + " ";
    }

    return str;
}

std::string mat_to_str_double(const std::vector<std::vector<double>>& m){
    std::string str;
    for(ui32 j=0; j<m.size(); j++){
        for(ui32 i=0; i<m[0].size(); i++){
            str += std::to_string(m[j][i]) + " ";
        }
        str += "\n";
    }
    return str;
}

}; // namespace lbcrypto ends
