#pragma once
#include "Common/Defines.h"
#include "Common/BitVector.h"
#include "Common/ArrayView.h"
#include "BitPosition.h"
namespace osuCrypto
{
	//// a list of {{set size, bit size}}
	//std::vector<std::array<u64, 2>> binSizes
	//{
	//    {1<<12, 18},
	//    {1<<16, 19},
	//    {1<<20, 20},
	//    {1<<24, 21}
	//};



	struct SimpleParam1
	{

		double mBinScaler[2];
		u64 mNumHashes[2];

		u64 mMaxBinSize[2];
		u64 mNumBits[2];
		/*
		double mBinStashScaler;
		u64 mNumStashHashes;
		u64 mSenderBinStashSize;*/

		
	};

	class SimpleHasher1
	{
	public:
		SimpleHasher1();
		~SimpleHasher1();

		
		//typedef std::vector<u64,block> MtBin;
		//typedef std::vector<std::pair<u64, block>> MtBin;
		struct Bin
		{
			std::vector<u64> mIdx; //have many items in the bin
								   //hash index used for mIdx. Only use when combined hints
								   //one can think mIdx and hIdx as a pair <mIdx,hIdx>....
			std::vector<u64> hIdx;
			std::vector<BitPosition> mBits;//mBits[IdxParty]
			//std::vector<std::vector<block>> mValOPRF; mValOPRF[IdxParty][mIdx]
			std::vector<std::vector<ECpoint>> mValOPRF;

			Bin() : mIdx(), hIdx(), mBits(), mValOPRF() {}

			// 拷贝构造函数
    		Bin(const Bin& other) 
			{
        		mIdx = other.mIdx;
        		hIdx = other.hIdx;
        		mBits = other.mBits;

        		// 对 mValOPRF 中的每个向量进行拷贝
        		mValOPRF.resize(other.mValOPRF.size());
        		for (size_t i = 0; i < other.mValOPRF.size(); ++i) 
				{
            		mValOPRF[i] = other.mValOPRF[i];
        		}
    		}

    		// 赋值运算符重载
    		Bin& operator=(const Bin& other) 
			{
        		if (this != &other) 
				{ // 避免自我赋值
            		mIdx = other.mIdx;
            		hIdx = other.hIdx;
            		mBits = other.mBits;

            		// 对 mValOPRF 中的每个向量进行拷贝
            		mValOPRF.resize(other.mValOPRF.size());
            		for (size_t i = 0; i < other.mValOPRF.size(); ++i) 
					{
                		mValOPRF[i] = other.mValOPRF[i];
            		}
        		}
       			return *this;
    		}
		};
		u64  mRepSize, mInputBitSize, mN;
		u64 mBinCount[2], mMaxBinSize[2], mNumHashes[2], mNumBits[2];

		//mOpprfs[IdxParty][inputIdx][hIdx]
		//std::vector<std::vector<std::vector<block>>> mOprfs;
		u64 testMaxBinSize;
		std::vector<u64> realBinSizeCount1;
		std::vector<u64> realBinSizeCount2;

		std::unique_ptr<std::mutex[]> mMtx;
		std::vector<Bin> mBins;
		//block mHashSeed;
		SimpleParam1 mParams;
		void print(u64 idxParty, bool isIdx, bool isOPRF, bool isMap, bool isPos /*u64 opt = 0*/) const;

		u64 maxRealBinSize();

		void init(u64 n/* u64 opt*/);

		void insertBatch(
			ArrayView<u64> inputIdxs,
			MatrixView<u64> hashs);

		//void preHashedInsertItems(ArrayView<block> items, u64 itemIdx);
		//void insertItemsWithPhasing(ArrayView<block> items, u64 itemIdx);


		SimpleHasher1(const SimpleHasher1& other) 
		{
        	// 深度复制成员变量
        	mRepSize = other.mRepSize;
        	mInputBitSize = other.mInputBitSize;
        	mN = other.mN;
        	std::copy(other.mBinCount, other.mBinCount + 2, mBinCount);
        	std::copy(other.mMaxBinSize, other.mMaxBinSize + 2, mMaxBinSize);
        	std::copy(other.mNumHashes, other.mNumHashes + 2, mNumHashes);
        	std::copy(other.mNumBits, other.mNumBits + 2, mNumBits);
       	 	//mOprfs = other.mOprfs;
        	testMaxBinSize = other.testMaxBinSize;
        	realBinSizeCount1 = other.realBinSizeCount1;
        	realBinSizeCount2 = other.realBinSizeCount2;
        	mBins = other.mBins;
        	//mHashSeed = other.mHashSeed;
        	mParams = other.mParams;

        	// 复制 mMtx 的内容
        	// mMtx.reset(new std::mutex[2]);
        	// for (size_t i = 0; i < 2; ++i) 
			// {
            // 	mMtx[i].lock();
           	// 	mMtx[i].unlock();
        	// }
    	}


		 SimpleHasher1& operator=(const SimpleHasher1& other) 
		 {
        	if (this != &other) 
			{ // 避免自我赋值
            	// 深度复制成员变量
            	mRepSize = other.mRepSize;
            	mInputBitSize = other.mInputBitSize;
            	mN = other.mN;
            	std::copy(other.mBinCount, other.mBinCount + 2, mBinCount);
            	std::copy(other.mMaxBinSize, other.mMaxBinSize + 2, mMaxBinSize);
            	std::copy(other.mNumHashes, other.mNumHashes + 2, mNumHashes);
            	std::copy(other.mNumBits, other.mNumBits + 2, mNumBits);
            	//mOprfs = other.mOprfs;
            	testMaxBinSize = other.testMaxBinSize;
            	realBinSizeCount1 = other.realBinSizeCount1;
            	realBinSizeCount2 = other.realBinSizeCount2;
            	mBins = other.mBins;
            	//mHashSeed = other.mHashSeed;
            	mParams = other.mParams;

            	// 复制 mMtx 的内容
            	// mMtx.reset(new std::mutex[2]);
            	// for (size_t i = 0; i < 2; ++i) 
				// {
                // 	mMtx[i].lock();
                // 	mMtx[i].unlock();
            	// }
        	}
        	return *this;
    	}
	};

}
