#pragma once

#include "point.h"
#include "Crypto/PRNG.h"
#include <array>
#include <cstring>
#include <sodium.h>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>

//typedef std::pair<NTL::ZZ, NTL::ZZ> Ciphertext;


//void Encrypt(Ciphertext &ciphertext, const NTL::ZZ &plaintext, NTL::ZZ alpha, NTL::ZZ beta, NTL::ZZ p);
//void Mul(Ciphertext &dest, const Ciphertext &src1, const Ciphertext &src2, NTL::ZZ p);
//void PartialDecrypt(NTL::ZZ &decryption_share, const NTL::ZZ &c1 , NTL::ZZ a, NTL::ZZ p);
//void FullyDecrypt(NTL::ZZ &plaintext, const std::vector<NTL::ZZ> &decryption_shares, const NTL::ZZ &c2, NTL::ZZ p);

// 加密解密函数
void Encrypt(Ciphertext &cipher, const ECpoint &plaintext, const ECpoint &B);
void Homo_Add(Ciphertext &dest, const Ciphertext &src1, const Ciphertext &src2);
void PartialDecrypt(ECpoint &decryption_share, const ECpoint &c1, const ECscalar &a);
void FullyDecrypt(ECpoint &plaintext, const std::vector<ECpoint> &decryption_shares, const ECpoint &c2);

ECpoint block_to_point(const block &input);


//void bytesToBlocks(const unsigned char* bytes, size_t length, std::vector<block>& blocks) ;
//void blocksToBytes(const std::vector<block>& blocks, unsigned char* bytes); 


void tparty(u64 myIdx, u64 nParties, u64 setSize, u64 nTrials);