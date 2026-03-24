#pragma once
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/BitVector.h"
#include "Common/ArrayView.h"
#include "Common/MatrixView.h"
//#include <mutex>
#include <atomic>
#include <unordered_map>
//#define THREAD_SAFE_CUCKOO
#include <set>
#include "protocols/xzh26/crypto/point.h"

namespace osuCrypto
{

	class BitPosition
	{
	public:
		BitPosition();
		~BitPosition();


		u64 mRealBitSize, mMaxBitSize, mNumTrial;
		std::vector<u8> mPos; //key: bit location; value: index of 
		std::vector<u8> mMaps;

		void print() const;
		void init(/*u64 numRealCodeWord,*/ u64 numMaxBitSize);
		/*bool getMasks(std::vector<block>& codeword);
		void getMask(block& codeword, u8& mask);
		void getPosHelper(std::vector<block>& codewords, int length);
		void getPos(std::vector<block>& codewords, int length);
		void getPos1(std::vector<block>& codewords, int length);
		void getRandPos();
		int midIdx(std::vector<block>& codewords, int length);*/

		bool getMasks(std::vector<ECpoint>& codeword);
		void getMask(ECpoint& codeword, u8& mask);
		void getPosHelper(std::vector<ECpoint>& codewords, int length);
		void getPos(std::vector<ECpoint>& codewords, int length);
		void getPos1(std::vector<ECpoint>& codewords, int length);
		void getRandPos();
		int midIdx(std::vector<ECpoint>& codewords, int length);


		//void findPos(std::vector<block>& codewords);
		//int isSet(block& codeword, int pos);
		//void setBit(block& codeword, int pos);
		//bool TestBitN(__m128i value, int N);



		BitPosition(const BitPosition& other) 
		{
       	 	mRealBitSize = other.mRealBitSize;
        	mMaxBitSize = other.mMaxBitSize;
        	mNumTrial = other.mNumTrial;
        	mPos = other.mPos;
        	mMaps = other.mMaps;
    	}

    	// 赋值运算符重载
   	 	BitPosition& operator=(const BitPosition& other) 
		{
        	if (this != &other) 
			{ // 避免自我赋值
            	mRealBitSize = other.mRealBitSize;
            	mMaxBitSize = other.mMaxBitSize;
            	mNumTrial = other.mNumTrial;
            	mPos = other.mPos;
            	mMaps = other.mMaps;
        	}
        	return *this;
    	}

	};
}
