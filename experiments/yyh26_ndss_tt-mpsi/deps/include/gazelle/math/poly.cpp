
#include "poly.h"


using namespace std;

namespace lbcrypto {

    template Matrix<ui32> PowersOfBase(const ui32 * vec, const ui32 size, const ui32 baseBits, const ui64 q);
    template Matrix<ui64> PowersOfBase(const ui64 * vec, const ui32 size, const ui32 baseBits, const ui64 q);

    template <typename T>
    Matrix<T> PowersOfBase(const T * vec, const ui32 size, const ui32 baseBits, const ui64 q) {
        ui32 num_windows = 1 + floor(log2(q))/baseBits;
        Matrix<T> result(num_windows, size);
        for (ui32 i = 0; i < num_windows; i++) {
            T scale = ((ui64)1 << (i*baseBits)) % q;
            for (ui32 j = 0; j < size; j++)
                // TODO: Make this not slow
                result[i][j] = mod_mul_slow(vec[j], scale, q);
        }
        return result;
    };


    template Matrix<ui32> BaseDecompose(const ui32 * vec, const ui32 size, const ui32 window_size, const ui32 num_windows);
    template Matrix<ui64> BaseDecompose(const ui64 * vec, const ui32 size, const ui32 window_size, const ui32 num_windows);
    template <typename T>
    Matrix<T> BaseDecompose(const T * vec, const ui32 size, const ui32 window_size, const ui32 num_windows) {
        Matrix<T> result(num_windows, size);
        T mask = (1 << window_size) - 1;
        for(ui32 j=0; j<size; j++) {
            T curr_coeff = vec[j];
            for(ui32 i=0; i<num_windows; i++){
                result[i][j] = (curr_coeff & mask);
                curr_coeff = (curr_coeff >> window_size);
            }
        }
        return result;
    };


    template void automorph(ui32 * result, const ui32 * input, const ui32 * indices, ui32 size, ui32 rot);
    template void automorph(ui64 * result, const ui64 * input, const ui32 * indices, ui32 size, ui32 rot);
    template <typename T>
    void automorph(T * result, const T * input, const ui32 * indices, ui32 size, ui32 rot) {
        assert(((size-1)&size) == 0);  // size is power of 2
        ui32 mask = size-1;
        auto index = indices[rot];

        auto idx = (index + 1)/2 - 1;
        for (ui32 j = 0; j < size; j++) {
            //determines which power of primitive root unity we should switch to
            result[j] = input[idx];
            idx = (idx+index) & mask;
        }
    };


    template void automorph_pt(ui32 * result, const ui32 * input, ui32 phim, ui32 rot);
    template void automorph_pt(ui64 * result, const ui64 * input, ui32 phim, ui32 rot);
    template <typename T>
    void automorph_pt(T * result, const T * input, ui32 phim, ui32 rot) {
        ui32 phim_by_2 = phim/2;
        ui32 inner_mask = (phim_by_2-1);
        ui32 inner_rot = rot & inner_mask;
        bool flip = ((rot & phim_by_2) != 0);

        for(ui32 i=0; i<phim_by_2; i++) {
            ui32 source = (i+inner_rot) & inner_mask;
            if(flip){
                result[i] = input[source+phim_by_2];
                result[i+phim_by_2] = input[source];
            } else {
                result[i] = input[source];
                result[i+phim_by_2] = input[source+phim_by_2];
            }
        }
    };

}  // namespace lbcrypto
