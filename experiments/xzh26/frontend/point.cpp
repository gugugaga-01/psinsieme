// point.cpp
#include "point.h"
#include <iostream>

// 定义单位元常量（全零数组）
const ECpoint ZERO_POINT = {0};

// ------ 椭圆曲线点运算实现 ------
bool points_equal(const ECpoint& a, const ECpoint& b) {
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool is_identity(const ECpoint& point) {
    return points_equal(point, ZERO_POINT);
}

ECpoint point_random() {
    ECpoint p;
    crypto_core_ristretto255_random(p.data());
    return p;
}

ECpoint point_add(const ECpoint& a, const ECpoint& b) {
    ECpoint result;
    crypto_core_ristretto255_add(result.data(), a.data(), b.data());
    return result;
}

ECpoint point_sub(const ECpoint& a, const ECpoint& b) {
    ECpoint result;
    crypto_core_ristretto255_sub(result.data(), a.data(), b.data());
    return result;
}

ECpoint scalar_mul(const ECscalar& scalar, const ECpoint& point) {
    ECpoint result;
    crypto_scalarmult_ristretto255(result.data(), scalar.data(), point.data());
    return result;
}

ECpoint scalar_mul_base(const ECscalar& scalar) {
    ECpoint result;
    crypto_scalarmult_ristretto255_base(result.data(), scalar.data());
    return result;
}

// ------ 椭圆曲线标量运算实现 ------
ECscalar scalar_random() {
    ECscalar s;
    crypto_core_ristretto255_scalar_random(s.data());
    return s;
}

ECscalar scalar_negate(const ECscalar& a) {
    ECscalar result;
    crypto_core_ristretto255_scalar_negate(result.data(), a.data());
    return result;
}

ECscalar scalar_invert(const ECscalar& a) {
    ECscalar result;
    crypto_core_ristretto255_scalar_invert(result.data(), a.data());
    return result;
}

ECscalar scalar_add(const ECscalar& a, const ECscalar& b) {
    ECscalar result;
    crypto_core_ristretto255_scalar_add(result.data(), a.data(), b.data());
    return result;
}

ECscalar scalar_sub(const ECscalar& a, const ECscalar& b) {
    ECscalar result;
    crypto_core_ristretto255_scalar_sub(result.data(), a.data(), b.data());
    return result;
}

ECscalar scalar_mul_scalar(const ECscalar& a, const ECscalar& b) {
    ECscalar result;
    crypto_core_ristretto255_scalar_mul(result.data(), a.data(), b.data());
    return result;
}