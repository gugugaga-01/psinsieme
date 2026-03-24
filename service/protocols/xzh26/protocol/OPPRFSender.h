#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "SimpleHasher1.h"
#include "CuckooHasher1.h"
#include "BitPosition.h"
#include "binSet.h"
namespace osuCrypto
{


    class OPPRFSender
    {
    public:


        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        OPPRFSender();
        ~OPPRFSender();

		u64 mN, mParties, mStatSecParam, mNcoInputBlkSize;

        PRNG mPrng;
		
		Timer mTimer;
		double mPosBitsTime=0;//两个都是记录getpos的时间用的

		//std::vector<std::vector<block>> mmOPRF; //mValOPRF[bIdx][Idx]
		//std::vector<BaseOPPRF> mmBits;//mBits[bIdx]
		//std::vector<std::vector<block>> mNcoInputBuff;

        void init(u64 numParties, u64 setSize,  u64 statSecParam,
            const std::vector<Channel*>& chls,
            block seed);

        void init(u64 numParties, u64 setSize,u64 statSecParam,
            Channel & chl0,
            block seed);
		void getOPRFkeysSeperatedandTable(u64 IdxTheirParty, binSet& bins,const std::vector<ECpoint>& myOPRFValues);

		void sendSSTableBased(u64 IdxTheirParty, binSet& bins, std::vector<ECpoint>& plaintexts,  const std::vector<Channel*>& chls);
    };

}