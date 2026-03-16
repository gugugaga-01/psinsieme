#pragma once

#include <volePSI/RsOpprf.h>
#include "shared/crypto/defines.h"
#include "shared/crypto/paillier.h"

struct TMpsiBase
{
    u64 mNumberOfParties;
    u64 mThreshold;
    u64 mPartyID;
    u64 mSenderSize;
    u64 mRecverSize;
    u64 mValueByteLength = 0;
    u64 mNumThreads = 1;
    OcPRNG mPrng;
    bool mDebug = false; // Add debug flag

    u64 mPlaintextModulus;

    PubKey mPubKey;
    PrivKey mPrivKey;

    void init(u64 numberOfParties,
              u64 threshold,
              u64 partyID,
              u64 senderSize,
              u64 recverSize,
              block seed,
              bool debug);

    virtual void InitializeCrypto(u64 n, const ZZ &seed) = 0; // Pure virtual function
    virtual void Sync(std::vector<Socket> &chls) = 0;
};

class TMpsiMember : public TMpsiBase, public oc::TimerAdapter
{
public:
    Proto Run(span<block> inputs, std::vector<Socket> &chls);

    void InitializeCrypto(u64 n, const ZZ &seed) override;
    void Sync(std::vector<Socket> &chls) override;
};

class TMpsiLeader : public TMpsiBase, public oc::TimerAdapter
{
public:
    Proto Run(span<block> inputs, std::vector<Socket> &chls);

    void InitializeCrypto(u64 n, const ZZ &seed) override;
    void Sync(std::vector<Socket> &chls) override;
};
