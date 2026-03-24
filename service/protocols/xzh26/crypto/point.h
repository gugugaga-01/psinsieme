// point.h
#ifndef POINT_UTILS_H
#define POINT_UTILS_H

#include <array>
#include <vector>
#include <cstring>
#include <cstdint>
#include <sodium.h>


// 椭圆曲线点类型（压缩格式，32字节）
using ECpoint = std::array<unsigned char, crypto_core_ristretto255_BYTES>;
// 椭圆曲线标量类型（32字节）
using ECscalar = std::array<unsigned char, crypto_core_ristretto255_SCALARBYTES>;
// ElGamal 密文类型：一对椭圆曲线点 (C1, C2)
using Ciphertext = std::pair<ECpoint, ECpoint>;

// 定义单位元（无穷远点/零元）的常量
extern const ECpoint ZERO_POINT;

// --- 椭圆曲线点运算 ---
// 比较两点是否相等
bool points_equal(const ECpoint& a, const ECpoint& b);
// 检查点是否为单位元
bool is_identity(const ECpoint& point);
// 生成随机点
ECpoint point_random();
// 点加法: R = A + B
ECpoint point_add(const ECpoint& a, const ECpoint& b);
// 点减法: R = A - B
ECpoint point_sub(const ECpoint& a, const ECpoint& b);
// 标量乘点: R = k * P
ECpoint scalar_mul(const ECscalar& scalar, const ECpoint& point);
// 标量乘基点: R = k * G
ECpoint scalar_mul_base(const ECscalar& scalar);

// --- 椭圆曲线标量运算 ---
// 生成随机标量
ECscalar scalar_random();
// 标量取负: r = -a
ECscalar scalar_negate(const ECscalar& a);
// 标量求逆: r = a^{-1} (模 L)
ECscalar scalar_invert(const ECscalar& a);
// 标量加法: r = a + b (模 L)
ECscalar scalar_add(const ECscalar& a, const ECscalar& b);
// 标量减法: r = a - b (模 L)
ECscalar scalar_sub(const ECscalar& a, const ECscalar& b);
// 标量乘法: r = a * b (模 L)
ECscalar scalar_mul_scalar(const ECscalar& a, const ECscalar& b);

#endif // POINT_UTILS_H