#pragma once

#include "Common/Defines.h"
#include "Network/Channel.h"
//#include "NChooseOne/NcoOtExt.h"
#include "CuckooHasher1.h"
#include "SimpleHasher1.h"

namespace osuCrypto
{

	//struct BFParam
	//{
	//	double mBinScaler[2]; //first index is for init step, 2nd index for stash step
	//	u64 mNumHashes[2];
	//	u64 mSenderBinSize[2];
	//	/*
	//	double mBinStashScaler;
	//	u64 mNumStashHashes;
	//	u64 mSenderBinStashSize;*/
	//};

    class binSet
    {
    public:
		binSet();
        ~binSet();
		

        u64 mN, mParties, mMyIdx, mStatSecParam, mNcoInputBlkSize;// , mOtMsgBlkSize;
        block mHashingSeed;
		u64 mMaskSize;
		//u64 mOpt;

		std::vector<std::vector<block>> mNcoInputBuff; //hash(x)

	//	OPPRFSender aaa;
		//std::vector<block> mXsets;
		

		CuckooHasher1 mCuckooBins;
		SimpleHasher1 mSimpleBins;
      

		void init(u64 myIdx, u64 nParties, u64 setSize, u64 statSecParam/* u64 opt*/);

		void hashing2Bins(std::vector<block>& inputs, int numThreads);




		binSet(const binSet& other) 
		{
        	// 深度复制成员变量
        	mN = other.mN;
        	mParties = other.mParties;
        	mMyIdx = other.mMyIdx;
        	mStatSecParam = other.mStatSecParam;
        	mNcoInputBlkSize = other.mNcoInputBlkSize;
       	 	mHashingSeed = other.mHashingSeed;
        	mMaskSize = other.mMaskSize;
        	//mOpt = other.mOpt;

        	// 深度复制 mNcoInputBuff
        	mNcoInputBuff = other.mNcoInputBuff;
        	// 深度复制 mXsets
        	//mXsets = other.mXsets;

        	// 使用拷贝构造函数复制 mCuckooBins 和 mSimpleBins
        	mCuckooBins = other.mCuckooBins;
        	mSimpleBins = other.mSimpleBins;		
    	}

		binSet& operator=(const binSet& other) 
		{
        	if (this != &other) { // 避免自我赋值
            	// 深度复制成员变量
           	 	mN = other.mN;
            	mParties = other.mParties;
            	mMyIdx = other.mMyIdx;
            	mStatSecParam = other.mStatSecParam;
            	mNcoInputBlkSize = other.mNcoInputBlkSize;
            	mHashingSeed = other.mHashingSeed;
            	mMaskSize = other.mMaskSize;
            	//mOpt = other.mOpt;

           	 	// 深度复制 mNcoInputBuff
            	mNcoInputBuff = other.mNcoInputBuff;
            	// 深度复制 mXsets
            	//mXsets = other.mXsets;

            	// 使用赋值运算符重载复制 mCuckooBins 和 mSimpleBins
            	mCuckooBins = other.mCuckooBins;
            	mSimpleBins = other.mSimpleBins;
        	}
        	return *this;
    	}
    };

}
