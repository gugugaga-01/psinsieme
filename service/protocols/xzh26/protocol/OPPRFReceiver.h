#pragma once

#include "Common/Defines.h"
#include "Network/Channel.h"
#include "CuckooHasher1.h"
#include "SimpleHasher1.h"
#include "binSet.h"

namespace osuCrypto
{

    class OPPRFReceiver
    {
    public:
        OPPRFReceiver();
        ~OPPRFReceiver();
        
        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

		
        u64 mN, mParties, mStatSecParam, mNcoInputBlkSize;// , mOtMsgBlkSize;
        //std::vector<u64> mIntersection;

		//std::vector<std::vector<block>> mNcoInputBuff;
        PRNG mPrng;
		
		void init(u64 numParties, u64 n, u64 statSecParam,Channel& chl0, block seed);
		void init(u64 numParties, u64 n, u64 statSecParam,const std::vector<Channel*>& chls, block seed);
		void getOPRFkeysSeperatedandTable(u64 IdxTheirParty, binSet& bins, const std::vector<ECpoint>& myOPRFValues);


		void recvSSTableBased(u64 IdxTheirParty, binSet& bins, std::vector<ECpoint>& plaintexts, const std::vector<Channel*>& chls);
    };




}
