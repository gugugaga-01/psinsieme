#include "OPPRFReceiver.h"
#include <future>

#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"

#include "Common/Log.h"
#include "Common/Log1.h"
//#include "Base/naor-pinkas.h"
#include <unordered_map>

//#include "TwoChooseOne/IknpOtExtReceiver.h"
//#include "TwoChooseOne/IknpOtExtSender.h"   libOTe
#include "Hashing/BitPosition.h"


//#define PRINT
namespace osuCrypto
{
	OPPRFReceiver::OPPRFReceiver()
	{
	}

	OPPRFReceiver::~OPPRFReceiver()
	{
	}

	void OPPRFReceiver::init(u64 numParties,
		u64 n,
		u64 statSec,
		Channel & chl0,
		block seed)
	{
		init(numParties, n, statSec, { &chl0 }, seed);
	}


	void OPPRFReceiver::init(u64 numParties,
		u64 n,
		u64 statSecParam,
		const std::vector<Channel*>& chls,
		block seed)
	{
		mParties = numParties;
		mStatSecParam = statSecParam;
		mN = n;
		mPrng.SetSeed(seed);
		//std::cout << "OPPRFReceiver init" << std::endl;
	}

	void OPPRFReceiver::getOPRFkeysSeperatedandTable(u64 IdxP, binSet& bins, const std::vector<ECpoint>& myOPRFValues)
	{
#if 1
		// this is the online phase.
		gTimer.setTimePoint("online.recv.start");


		std::vector<std::thread>  thrds(1);
		//  std::vector<std::thread>  thrds(1);

		// fr each thread, spawn it.
		for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
		{
			auto seed = mPrng.get<block>();
			//std::cout << "getOPRFkeys start" << std::endl;
			thrds[tIdx] = std::thread([&, tIdx, seed]()
			{

				if (tIdx == 0) gTimer.setTimePoint("online.recv.thrdStart");



				//auto& chl = *chls[tIdx];

				//if (tIdx == 0) gTimer.setTimePoint("online.recv.insertDone");

				const u64 stepSize = 16;

				//std::vector<block> ncoInput(bins.mNcoInputBlkSize);

#if 1
#pragma region compute Recv Bark-OPRF

				//####################
				//#######Recv role
				//####################
				//auto& otRecv = *mOtRecvs[tIdx];

				auto CountRecv = bins.mCuckooBins.mBins.size();
				// get the region of the base OTs that this thread should do.
				auto binStart = tIdx       * CountRecv / thrds.size();
				auto binEnd = (tIdx + 1) * CountRecv / thrds.size();

				for (u64 bIdx = binStart; bIdx < binEnd;)
				{
					u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

					for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
					{
						auto& bin = bins.mCuckooBins.mBins[bIdx];

						if (!bin.isEmpty())//非空桶
						{
							u64 inputIdx = bin.idx();
							if (inputIdx >= myOPRFValues.size()) {
                            throw std::runtime_error("Input index out of bounds");
						}
                        
                        	bin.mValOPRF[IdxP] = myOPRFValues[inputIdx];
							//#ifdef DEBUG_OPRF
							//std::cout << "Recv DH-OPRF: bin " << bIdx 
									//<< ", inputIdx " << inputIdx 
									//<< ", OPRF value stored" << std::endl;
							//#endif

							/*for (u64 j = 0; j < ncoInput.size(); ++j)
								ncoInput[j] = bins.mNcoInputBuff[j][inputIdx];

							otRecv.encode(
								bIdx,      // input
								ncoInput,             // input
								bin.mValOPRF[IdxP]); // output*/
						}
						else
						{
							//otRecv.zeroEncode(bIdx);
							//memcpy(bin.mValOPRF[IdxP].data(), ZERO_POINT.data(), 
                               //crypto_core_ristretto255_BYTES);
							bin.mValOPRF.push_back(ZERO_POINT);
							//#ifdef DEBUG_OPRF
							//std::cout << "Recv DH-OPRF: empty bin " << bIdx
									//<< ", set to zero" << std::endl;
							//#endif
						}
					}
					//otRecv.sendCorrection(chl, currentStepSize);
				}

				if (tIdx == 0) gTimer.setTimePoint("online.recv.Recv.finalOPRF");



#pragma endregion
#endif

#if 1
#pragma region compute Send Bark-OPRF
#pragma endregion
#endif
				//otRecv.check(chl);
			});
		}

		// join the threads.
		for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
			thrds[tIdx].join();
		//同步线程
		gTimer.setTimePoint("online.recv.exit");

		//std::cout << gTimer;
#endif
	}
	void OPPRFReceiver::recvSSTableBased(u64 IdxP, binSet& bins, std::vector<ECpoint>& plaintexts, const std::vector<Channel*>& chls)
	{

		// this is the online phase.
		gTimer.setTimePoint("online.recv.start");

		//u64 maskSize = sizeof(block);// roundUpTo(mStatSecParam + 2 * std::log(mN) - 1, 8) / 8;
		//u64 numBitLoc = bins.mSimpleBins.mNumBits[1];
		


		std::vector<std::thread>  thrds(chls.size());
		//std::cout << "recvSSTable start" << std::endl;
		// this mutex is used to guard inserting things into the intersection vector.
		//std::mutex mInsertMtx;

		// fr each thread, spawn it.
		for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
		{
			auto seed = mPrng.get<block>();
			//std::cout << "recvSSTable thread start" << std::endl;
			thrds[tIdx] = std::thread([&, tIdx, seed]()
			{
				if (tIdx == 0) gTimer.setTimePoint("online.recv.thrdStart");

				auto& chl = *chls[tIdx];
				const u64 stepSize = 16;

				if (tIdx == 0) gTimer.setTimePoint("online.recv.recvShare");
				//创建线程，互斥锁

				//2 type of bins: normal bin in inital step + stash bin
				for (auto bIdxType = 0; bIdxType < 2; bIdxType++)
				//循环处理两种桶
				{
					auto binCountRecv = bins.mCuckooBins.mBinCount[bIdxType];
					//bins.mMaskSize = roundUpTo(mStatSecParam + std::log2(bins.mSimpleBins.mMaxBinSize[bIdxType]), 8) / 8;

					u64 binStart, binEnd;
					if (bIdxType == 0)
					{
						binStart = tIdx       * binCountRecv / thrds.size();
						binEnd = (tIdx + 1) * binCountRecv / thrds.size();
					}
					else
					{
						binStart = tIdx       * binCountRecv / thrds.size() + bins.mCuckooBins.mBinCount[0];
						binEnd = (tIdx + 1) * binCountRecv / thrds.size() + bins.mCuckooBins.mBinCount[0];
					}
					



					//use the params of the simple hashing as their params
					u64 mTheirBins_mMaxBinSize = bins.mSimpleBins.mMaxBinSize[bIdxType];
					u64 mTheirBins_mNumBits = bins.mSimpleBins.mNumBits[bIdxType];
					//std::cout << "table param compute start" << std::endl;
					//处理发送方的参数解析消息
					for (u64 bIdx = binStart; bIdx < binEnd;)
					{
						u64 curStepSize = std::min(stepSize, binEnd - bIdx);
						MatrixView<u8> maskView;
						ByteStream maskBuffer;
						//std::cout << "buffer recv start" << std::endl;
						chl.recv(maskBuffer);
						//maskView = maskBuffer.getMatrixView<u8>(mTheirBins_mMaxBinSize * maskSize + mTheirBins_mNumBits * sizeof(u8));
						maskView = maskBuffer.getMatrixView<u8>(mTheirBins_mMaxBinSize * bins.mMaskSize + mTheirBins_mNumBits * sizeof(u8));
						//解析缓冲区得到矩阵视图
						if (maskView.size()[0] != curStepSize)
							throw std::runtime_error("size not expedted");

						for (u64 stepIdx = 0; stepIdx < curStepSize; ++bIdx, ++stepIdx)
						//处理每个桶，计算掩码查询解密
						{

							auto& bin = bins.mCuckooBins.mBins[bIdx];
							if (!bin.isEmpty())
							{
								u64 baseMaskIdx = stepIdx;
								//auto mask = maskView[baseMaskIdx];
								BitPosition b;
								b.mMaxBitSize = mTheirBins_mNumBits;
								for (u64 i = 0; i < b.mMaxBitSize; i++)
								{
									int idxPos = 0;
									memcpy(&idxPos, maskView[baseMaskIdx].data() + i, sizeof(u8));
									b.mPos.push_back(idxPos);
								}
#ifdef PRINT
								Log::out << "RBin #" << bIdx << Log::endl;
								Log::out << "    cc_mPos= ";
								for (u64 idxPos = 0; idxPos < b.mPos.size(); idxPos++)
								{
									Log::out << static_cast<int16_t>(b.mPos[idxPos]) << " ";
								}
								Log::out << Log::endl;
								//日志
#endif
								u64 inputIdx = bin.idx();
								auto myMask = bin.mValOPRF[IdxP];
								//	u8 myMaskPos = 0;
								b.getMask(myMask, bin.mValMap[IdxP]);

								u64	MaskIdx = bin.mValMap[IdxP] * bins.mMaskSize + mTheirBins_mNumBits;

								auto theirMask = ZERO_POINT;
								memcpy(&theirMask, maskView[baseMaskIdx].data() + MaskIdx, bins.mMaskSize);
								//提取对应索引的加密块

								//if (!memcmp((u8*)&myMask, &theirMask, maskSize))
								//{
								//Log::out << "inputIdx: " << inputIdx << Log::endl;
								//	Log::out << "myMask: " << myMask << Log::endl;
								//Log::out << "theirMask: " << theirMask << " " << Log::endl;


								//plaintexts[inputIdx] = myMask^theirMask;
								plaintexts[inputIdx] = point_sub(theirMask, myMask);
								//异或解密


								//}
							}
						}
					}
				}


			});
			//	if (tIdx == 0) gTimer.setTimePoint("online.recv.done");
		}
		// join the threads.
		for (auto& thrd : thrds)
			thrd.join();//进程同步

		// check that the number of inputs is as expected.
		if (plaintexts.size() != mN)
			throw std::runtime_error(LOCATION);//检查明文数量是否与输入数量一致



	}
}