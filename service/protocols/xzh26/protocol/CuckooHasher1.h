#pragma once
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/BitVector.h"
#include "Common/ArrayView.h"
#include "Common/MatrixView.h"
#include "BitPosition.h"
#include "protocols/xzh26/crypto/point.h"
//#include <mutex>
#include <atomic>

//#define THREAD_SAFE_CUCKOO

namespace osuCrypto
{
    struct CuckooParam1
    {
        double mBinScaler[2]; //first index is for init step, 2nd index for stash step
		u64 mNumHashes[2];
		u64 mSenderBinSize[2];
/*
		double mBinStashScaler;
		u64 mNumStashHashes;
		u64 mSenderBinStashSize;*/

    };



    class CuckooHasher1
    {
    public:
        CuckooHasher1();
        ~CuckooHasher1();

        struct Bin
        {
            Bin() :mVal(-1) {}
            Bin(u64 idx, u64 hashIdx) : mVal(idx | (hashIdx << 56)) {}

            bool isEmpty() const;
            u64 idx() const;
            u64 hashIdx() const;

            void swap(u64& idx, u64& hashIdx);
#ifdef THREAD_SAFE_CUCKOO
            Bin(const Bin& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            Bin(Bin&& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            std::atomic<u64> mVal;
#else
            //Bin(const Bin& b) : mVal(b.mVal) {}
            Bin(Bin&& b) : mVal(b.mVal) {}
            u64 mVal;
			//std::vector<block> mValOPRF;
            std::vector<ECpoint> mValOPRF;
			std::vector<u8> mValMap;

			//std::vector<std::vector<block>> mCoeffs;//mBits[IdxParty][mIdx]

            Bin(const Bin& other)
                : mVal(other.mVal), 
                mValOPRF(other.mValOPRF),
                mValMap(other.mValMap)
                //mCoeffs(other.mCoeffs) 
                {}

            Bin& operator=(const Bin& b) 
            {
                if (this != &b) 
                { // 避免自我赋值
                    mVal = b.mVal;
                    mValOPRF = b.mValOPRF;
                    mValMap = b.mValMap;
                    //mCoeffs = b.mCoeffs;
                }
                return *this;
            }
#endif
        };
        struct Workspace
        {
            Workspace(u64 n)
                : curAddrs(n)
                , curHashIdxs(n)
                , oldVals(n)
                //, findAddr(n)
                , findVal(n)
            {}

            std::vector<u64>
                curAddrs,// (inputIdxs.size(), 0),
                curHashIdxs,// (inputIdxs.size(), 0),
                oldVals;// (inputIdxs.size());

            std::vector<std::array<u64, 2>> /*findAddr,*/ findVal;


            Workspace(const Workspace& other)
                : curAddrs(other.curAddrs),
                curHashIdxs(other.curHashIdxs),
                oldVals(other.oldVals),
                findVal(other.findVal) {}

            // 赋值运算符重载
            Workspace& operator=(const Workspace& other) 
            {
                if (this != &other) 
                { // 避免自我赋值
                    curAddrs = other.curAddrs;
                    curHashIdxs = other.curHashIdxs;
                    oldVals = other.oldVals;
                    findVal = other.findVal;
                }
                return *this;
            }
        };


		std::mutex mInsertBin;
        u64 mTotalTries;

        bool operator==(const CuckooHasher1& cmp)const;
        bool operator!=(const CuckooHasher1& cmp)const;

        //std::mutex mStashx;

        CuckooParam1 mParams;
		//block mHashSeed;
		u64  mRepSize, mInputBitSize, mN;
		u64 mBinCount[2];//mBinCount[0] for init step, mBinCount[1] for Stash step
        void print(u64 IdxParty, bool isIdx, bool isOPRF, bool isMap) const;
		void init(u64 n/*u64 opt*/);
        void insert(u64 IdxItem, ArrayView<u64> hashes);
        void insertHelper(u64 IdxItem, u64 hashIdx, u64 numTries);
		void insertStashHelper(u64 IdxItem, u64 hashIdx, u64 numTries);

        void insertBatch(ArrayView<u64> itemIdxs, MatrixView<u64> hashs, Workspace& workspace);

		
			void insertStashBatch(ArrayView<u64> itemIdxs, MatrixView<u64> hashs, Workspace& workspace);


        u64 find(ArrayView<u64> hashes);
        u64 findBatch(MatrixView<u64> hashes, 
            ArrayView<u64> idxs,
            Workspace& wordkspace);

   // private:

        std::vector<u64> mHashes;
        MatrixView<u64> mHashesView;

		std::vector<u64> mStashHashes;
		MatrixView<u64> mStashHashesView;

        std::vector<Bin> mBins;
        std::vector<Bin> mStashBins;
		std::vector<u64> mStashIdxs;

        //std::vector<Bin> mBins;
        //std::vector<Bin> mStash;


        //void insertItems(std::array<std::vector<block>,4>& hashs);



        CuckooHasher1(const CuckooHasher1& other) 
        {
            // 深度复制成员变量
            mTotalTries = other.mTotalTries;
            mParams = other.mParams;
            //mHashSeed = other.mHashSeed;
            mRepSize = other.mRepSize;
            mInputBitSize = other.mInputBitSize;
            mN = other.mN;
            std::copy(other.mBinCount, other.mBinCount + 2, mBinCount);
            mHashes = other.mHashes;
            mStashHashes = other.mStashHashes;
            mBins = other.mBins;
            mStashBins = other.mStashBins;
            mStashIdxs = other.mStashIdxs;
            // Rebuild views from our copied data
            if (!mHashes.empty())
                mHashesView = MatrixView<u64>(mHashes.begin(), mHashes.end(), other.mHashesView.size()[1]);
            if (!mStashHashes.empty())
                mStashHashesView = MatrixView<u64>(mStashHashes.begin(), mStashHashes.end(), other.mStashHashesView.size()[1]);
        }

        CuckooHasher1& operator=(const CuckooHasher1& other)
        {
            if (this != &other)
            {
                mTotalTries = other.mTotalTries;
                mParams = other.mParams;
                mRepSize = other.mRepSize;
                mInputBitSize = other.mInputBitSize;
                mN = other.mN;
                std::copy(other.mBinCount, other.mBinCount + 2, mBinCount);
                mHashes = other.mHashes;
                mStashHashes = other.mStashHashes;
                mBins = other.mBins;
                mStashBins = other.mStashBins;
                mStashIdxs = other.mStashIdxs;
                if (!mHashes.empty())
                    mHashesView = MatrixView<u64>(mHashes.begin(), mHashes.end(), other.mHashesView.size()[1]);
                if (!mStashHashes.empty())
                    mStashHashesView = MatrixView<u64>(mStashHashes.begin(), mStashHashes.end(), other.mStashHashesView.size()[1]);
            }
            return *this;
        }



    };

}
