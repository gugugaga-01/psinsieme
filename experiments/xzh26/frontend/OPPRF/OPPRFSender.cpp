#include "OPPRFSender.h"

#include <algorithm>
#include "Crypto/Commit.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include "Common/Timer.h"
namespace osuCrypto
{

	OPPRFSender::OPPRFSender()
	{
	}
	//const u64 OPPRFSender::hasherStepSize(128);


	OPPRFSender::~OPPRFSender()
	{
	}

	void OPPRFSender::init(u64 numParties, u64 setSize, u64 statSec,
		Channel & chl0,
		block seed)
	{
		init(numParties, setSize, statSec,{ &chl0 }, seed);
	}


	void OPPRFSender::init(u64 numParties, u64 setSize, u64 statSec,
		const std::vector<Channel*>& chls,
		block seed)
	{
		mStatSecParam = statSec;
		mN = setSize;
		mParties = numParties;
		mPrng.SetSeed(seed);
	}

	void  OPPRFSender::getOPRFkeysSeperatedandTable(u64 IdxP, binSet& bins, const std::vector<ECpoint>& myOPRFValues)
	{

		//std::vector<std::thread>  thrds(chls.size());
		std::vector<std::thread>  thrds(1);

		gTimer.setTimePoint("online.send.spaw");


		for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
		{
			auto seed = mPrng.get<block>();
			thrds[tIdx] = std::thread([&, tIdx, seed]() {

				PRNG prng(seed);

				if (tIdx == 0) gTimer.setTimePoint("online.send.thrdStart");


				//auto& chl = *chls[tIdx];

				//if (tIdx == 0) gTimer.setTimePoint("online.send.insert");
				const u64 stepSize = 16;

				//std::vector<block> ncoInput(bins.mNcoInputBlkSize);

#if 1
#pragma region compute Send Bark-OPRF				
				//####################
				//#######Sender role
				//####################
				//auto& otSend = *mOtSends[tIdx];
				auto CountSend = bins.mSimpleBins.mBins.size();

				auto binStart = tIdx       * CountSend / thrds.size();
				auto binEnd = (tIdx + 1) * CountSend / thrds.size();

				if (tIdx == 0) gTimer.setTimePoint("online.send.OPRF");

				for (u64 bIdx = binStart; bIdx < binEnd;)
				{
					u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
					//otSend.recvCorrection(chl, currentStepSize);

					for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
					{

						auto& bin = bins.mSimpleBins.mBins[bIdx];

						if (bin.mIdx.size() > 0)
						{
							bin.mValOPRF[IdxP].resize(bin.mIdx.size());
							//std::cout << "s-" << bIdx << ", ";
							for (u64 i = 0; i < bin.mIdx.size(); ++i)
							{

								u64 inputIdx = bin.mIdx[i];

								// DH-OPRF: 从预计算的OPRF值向量中获取对应值
								if (inputIdx >= myOPRFValues.size()) {
									throw std::runtime_error("Input index out of bounds");
								}
								
								bin.mValOPRF[IdxP][i] = myOPRFValues[inputIdx];
								
								//#ifdef DEBUG_OPRF
								//std::cout << "  Element " << i << ": inputIdx=" << inputIdx 
										//<< ", OPRF value stored" << std::endl;
								//#endif
							}

							//#####################
							//######Finding bit locations
							//#####################

							//std::cout << bin.mValOPRF[IdxP][0];

							//diff max bin size for first mSimpleBins.mBinCount and 
							// mSimpleBins.mBinStashCount
							if (bIdx < bins.mSimpleBins.mBinCount[0])
								bin.mBits[IdxP].init(/*bin.mIdx.size(), */bins.mSimpleBins.mNumBits[0]);
							else
								bin.mBits[IdxP].init(/*bin.mIdx.size(), */bins.mSimpleBins.mNumBits[1]);

							auto start = mTimer.setTimePoint("getPos1.start");
							bin.mBits[IdxP].getPos1(bin.mValOPRF[IdxP], 256);
							auto end = mTimer.setTimePoint("getPos1.done");

							mPosBitsTime += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
							//std::cout << "getPosTime" << IdxP << ": " << mPosBitsTime / pow(10, 6) << std::endl;

							//bin.mBits[IdxP].getMasks(bin.mValOPRF[IdxP]);
							//std::cout << ", "
							//	<< static_cast<int16_t>(bin.mBits[IdxP].mMaps[0]) << std::endl;
						}
					}
				}


				if (tIdx == 0) gTimer.setTimePoint("online.send.otSend.finalOPRF");

#ifdef PRINT
				std::cout << "getPosTime" << IdxP << ": " << mPosBitsTime / pow(10, 6) << std::endl;
#endif // PRINT


#pragma endregion
#endif

#if 1
#pragma region compute Recv Bark-OPRF
#pragma endregion
#endif
				//otSend.check(chl);

			});
		}

		for (auto& thrd : thrds)
			thrd.join();
	}

	void OPPRFSender::sendSSTableBased(u64 IdxP, binSet& bins, std::vector<ECpoint>& plaintexts, const std::vector<Channel*>& chls)
	{
		if (plaintexts.size() != mN)
			throw std::runtime_error(LOCATION);
		//验证输入集合大小

		
		std::vector<std::thread>  thrds(chls.size());
		// std::vector<std::thread>  thrds(1);        

		//std::mutex mtx;


		gTimer.setTimePoint("online.send.spaw");

		for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
		{
			auto seed = mPrng.get<block>();
			thrds[tIdx] = std::thread([&, tIdx, seed]() {

				PRNG prng(seed);

				if (tIdx == 0) gTimer.setTimePoint("online.send.thrdStart");

				auto& chl = *chls[tIdx];
				const u64 stepSize = 16;

#pragma region sendShare
#if 1
				if (tIdx == 0) gTimer.setTimePoint("online.send.sendShare");

				//2 type of bins: normal bin in inital step + stash bin
				for (auto bIdxType = 0; bIdxType < 2; bIdxType++)
				{
					auto binCountSend = bins.mSimpleBins.mBinCount[bIdxType];
					//bins.mMaskSize = roundUpTo(mStatSecParam + std::log2(bins.mSimpleBins.mMaxBinSize[bIdxType]), 8) / 8;

					u64 binStart, binEnd;
					if (bIdxType == 0)
					{
						binStart = tIdx       * binCountSend / thrds.size();
						binEnd = (tIdx + 1) * binCountSend / thrds.size();
					}
					else
					{
						binStart = tIdx       * binCountSend / thrds.size() + bins.mSimpleBins.mBinCount[0];
						binEnd = (tIdx + 1) * binCountSend / thrds.size() + bins.mSimpleBins.mBinCount[0];
					}

					if (tIdx == 0) gTimer.setTimePoint("online.send.masks.init.step");

					for (u64 bIdx = binStart; bIdx < binEnd;)
					{
						u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
						uPtr<Buff> sendMaskBuff(new Buff);
						sendMaskBuff->resize(currentStepSize * (bins.mSimpleBins.mMaxBinSize[bIdxType] * bins.mMaskSize + bins.mSimpleBins.mNumBits[bIdxType] * sizeof(u8)));
						auto maskView = sendMaskBuff->getMatrixView<u8>(bins.mSimpleBins.mMaxBinSize[bIdxType] * bins.mMaskSize + bins.mSimpleBins.mNumBits[bIdxType] * sizeof(u8));

						for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
						{
							//Log::out << "sBin #" << bIdx << Log::endl;

							auto& bin = bins.mSimpleBins.mBins[bIdx];
							u64 baseMaskIdx = stepIdx;
							int MaskIdx = 0;

							if (bin.mIdx.size() > 0)
							{
								//copy bit locations in which all OPRF values are distinct

								//	Log::out << "    c_mPos= ";

								if (bin.mBits[IdxP].mPos.size() != bins.mSimpleBins.mNumBits[bIdxType])
								{
#ifdef PRINT
									Log::out << "bin.mBits[IdxP].mPos.size() != bins.mSimpleBins.mNumBits[bIdxType]" << Log::endl;
									Log::out << "Party: " << IdxP << Log::endl;
									Log::out << "bIdx: " << bIdx << Log::endl;
									Log::out << "bin.mBits[IdxP].mPos.size(): " << bin.mBits[IdxP].mPos.size() << Log::endl;
									Log::out << "mSimpleBins.mNumBits[bIdxType]: " << bins.mSimpleBins.mNumBits[bIdxType] << Log::endl;
#endif // PRINT
									throw std::runtime_error("bin.mBits.mPos.size()!= mBins.mNumBits");

								}

								//copy bit positions
								for (u64 idxPos = 0; idxPos < bin.mBits[IdxP].mPos.size(); idxPos++)
								{
									//	Log::out << static_cast<int16_t>(bin.mBits[IdxP].mPos[idxPos]) << " ";
									memcpy(
										maskView[baseMaskIdx].data() + idxPos,
										(u8*)&bin.mBits[IdxP].mPos[idxPos], sizeof(u8));
								}
								//Log::out << Log::endl;


								for (u64 i = 0; i < bin.mIdx.size(); ++i)
								{
									u64 inputIdx = bin.mIdx[i];
									//block encr = bin.mValOPRF[IdxP][i] ^ plaintexts[inputIdx];
									ECpoint encr = point_add(bin.mValOPRF[IdxP][i], plaintexts[inputIdx]);

									//Log::out << "    c_idx=" << inputIdx;
									//Log::out << "    c_OPRF=" << encr;
									//Log::out << "    c_Map=" << static_cast<int16_t>(bin.mBits.mMaps[i]);

									MaskIdx = bin.mBits[IdxP].mMaps[i] * bins.mMaskSize + bins.mSimpleBins.mNumBits[bIdxType];

									memcpy(
										maskView[baseMaskIdx].data() + MaskIdx,
										encr.data(),
										bins.mMaskSize);

									//	Log::out << Log::endl;
								}

								//#####################
								//######Filling dummy mask
								//#####################

								for (u64 i = 0; i < bins.mSimpleBins.mMaxBinSize[bIdxType]; ++i)
								{
									if (std::find(bin.mBits[IdxP].mMaps.begin(), bin.mBits[IdxP].mMaps.end(), i) == bin.mBits[IdxP].mMaps.end())
									{
										MaskIdx = i* bins.mMaskSize + bins.mSimpleBins.mNumBits[bIdxType];
										//	Log::out << "    cc_Map=" << i << Log::endl;
										/*memcpy(
											maskView[baseMaskIdx].data() + MaskIdx,
											(u8*)&ZeroBlock,  //make randome
											bins.mMaskSize);*/
										memcpy(maskView[baseMaskIdx].data() + MaskIdx,
                                           ZERO_POINT.data(),
                                           bins.mMaskSize);
									}
								}
							}
							else //pad all dummy
							{
								//bit positions
								std::vector<u8> dummyPos;
								auto idxDummyPos = 0;
								while (dummyPos.size()<bins.mSimpleBins.mNumBits[bIdxType])
								{
									u64 rand = std::rand() % 128; //choose randome bit location
									if (std::find(dummyPos.begin(), dummyPos.end(), rand) == dummyPos.end())
									{
										dummyPos.push_back(rand);
										memcpy(
											maskView[baseMaskIdx].data() + idxDummyPos,
											(u8*)&rand, sizeof(u8));
										idxDummyPos++;
									}
								}

								for (u64 i = 0; i < bins.mSimpleBins.mMaxBinSize[bIdxType]; ++i)
								{
									MaskIdx = i* bins.mMaskSize + bins.mSimpleBins.mNumBits[bIdxType];
									//	Log::out << "    cc_Map=" << i << Log::endl;
									memcpy(
										maskView[baseMaskIdx].data() + MaskIdx,
										ZERO_POINT.data(),  //make randome
										bins.mMaskSize);

								}

							}


						}

#ifdef PRINT
						Log::out << "bins.mMaskSize: ";
						for (size_t i = 0; i < maskView.size()[0]; i++)
						{
							for (size_t j = 0; j < mSimpleBins.mNumBits[bIdxType]; j++)
							{
								Log::out << static_cast<int16_t>(maskView[i][j]) << " ";
							}
							Log::out << Log::endl;

							for (size_t j = 0; j < mSimpleBins.mMaxBinSize[bIdxType]; j++) {
								auto theirMask = ZeroBlock;
								memcpy(&theirMask, maskView[i].data() + j*bins.mMaskSize + mSimpleBins.mNumBits[bIdxType], bins.mMaskSize);
								if (theirMask != ZeroBlock)
								{
									Log::out << theirMask << " " << Log::endl;
								}
							}
						}
#endif
						chl.asyncSend(std::move(sendMaskBuff));

					}
				}
				if (tIdx == 0) gTimer.setTimePoint("online.send.sendMask");

				//	otSend.check(chl);



				/* if (tIdx == 0)
				chl.asyncSend(std::move(sendMaskBuff));*/

				if (tIdx == 0) gTimer.setTimePoint("online.send.finalMask");
#endif
#pragma endregion

			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		//    permThrd.join();



	}
}


