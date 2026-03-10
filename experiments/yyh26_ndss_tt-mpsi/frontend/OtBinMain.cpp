#include "Network/BtEndpoint.h"

#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "Common/Defines.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "NChooseOne/Oos/OosNcoOtReceiver.h"
#include "NChooseOne/Oos/OosNcoOtSender.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <numeric>
#include <iostream>
#include <dirent.h>
// #define OOS
// #define PRINT
#define pows {16 /*8,12,,20*/}
#define threadss {1 /*1,4,16,64*/}
#define numTrial 2
#include <thread>
#include <mutex>
#include <future>

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <time.h>

#include "../libOLE/third_party/cryptoTools/cryptoTools/Common/Timer.h"
#include "../libOLE/third_party/cryptoTools/cryptoTools/Common/Log.h"

#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Channel.h"
#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Session.h"
#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/IOService.h"

#include "../libOLE/src/lib/pke/ole.h"
#include "../libOLE/src/lib/pke/gazelle-network.h"
#include "../libOLE/src/lib/utils/debug.h"
#include <boost/multiprecision/cpp_int.hpp>

using namespace lbcrypto;
using namespace osuCryptoNew;
const double std_dev = 3.2;

std::vector<NTL::ZZ_p> ShareSecret(const NTL::ZZ_p secret, u64 numShares, u64 threshold, NTL::ZZ p)
{
	//  std::cout<<"origin secret = " << secret<<std::endl;

	NTL::SetSeed(p);
	NTL::ZZ_p::init(p);
	std::vector<NTL::ZZ_p> shares(numShares);
	// std::cout<<"origin secret = " << secret<<std::endl;
	NTL::ZZ secret_mod_p = NTL::conv<NTL::ZZ>(secret) % p;

	// std::cout<<"secret = " << secret_mod_p<<", p = " << p <<std::endl;
	NTL::ZZ_pX poly;
	NTL::SetCoeff(poly, 0, NTL::conv<NTL::ZZ_p>(secret_mod_p));

	for (long i = 1; i < threshold; i++)
	{
		NTL::ZZ coef;
		NTL::RandomBnd(coef, p);
		NTL::SetCoeff(poly, i, NTL::conv<NTL::ZZ_p>(coef));
	}
	// std::cout << "The zz_pX polynomial is: " << poly << std::endl;

	for (long i = 0; i < numShares; i++)
	{
		shares[i] = NTL::eval(poly, NTL::to_ZZ_p(i + 1));
	}

	return shares;
}

std::vector<NTL::ZZ_p> GenerateUpdateValues(u64 numShares, u64 threshold, NTL::ZZ p)
{

	NTL::ZZ_p::init(p);
	std::vector<NTL::ZZ_p> updates_values;
	updates_values.resize(numShares);
	NTL::ZZ_pX poly;
	NTL::SetCoeff(poly, 0, 0);
	for (int j = 1; j < threshold; j++) // form a poly f(x) = 0 + a_1*x + a_{t-1}*x^{t-1}
	{
		NTL::ZZ coef;
		NTL::RandomBnd(coef, p);
		NTL::SetCoeff(poly, j, NTL::conv<NTL::ZZ_p>(coef));
	}
	// std::cout << "The zz_pX polynomial is: " << poly << std::endl;

	for (int j = 0; j < numShares; j++)
	{
		updates_values[j] = NTL::eval(poly, NTL::to_ZZ_p(j + 1));
	}

	return updates_values;
}

__uint128_t ZZ_to_ui128(const NTL::ZZ &zz_value)
{

	uint8_t bytes[16] = {0};
	NTL::BytesFromZZ(bytes, zz_value, 16);

	__uint128_t result = 0;
	for (int i = 0; i < 16; i++)
	{
		result |= (__uint128_t)bytes[i] << (8 * i);
	}
	return result;
}

NTL::ZZ uint128_to_ZZ(__uint128_t value)
{

	NTL::ZZ result = NTL::conv<NTL::ZZ>("0");
	result.SetSize(128 / NTL_ZZ_NBITS);

	uint64_t high = static_cast<uint64_t>(value >> 64);
	uint64_t low = static_cast<uint64_t>(value);

	result += NTL::ZZ(high);
	result <<= 64;
	result += NTL::ZZ(low);
	return result;
}

NTL::ZZ lagrange_interpolation(const std::vector<std::pair<NTL::ZZ, NTL::ZZ>> &shares, NTL::ZZ mod)
{

	u64 t = shares.size();

	NTL::ZZ secret = NTL::ZZ(0);
	std::vector<NTL::ZZ> inverses(t, NTL::ZZ(1));
	std::vector<NTL::ZZ> neg_xj(t);

	//-xj % mod
	for (int j = 0; j < t; ++j)
	{
		neg_xj[j] = SubMod(mod, shares[j].first, mod);
	}

	for (int i = 0; i < t; ++i)
	{
		NTL::ZZ denominator = NTL::ZZ(1);
		for (int j = 0; j < t; ++j)
		{
			if (i != j)
			{
				NTL::ZZ diff = SubMod(shares[i].first, shares[j].first, mod);
				denominator = MulMod(denominator, diff, mod);
			}
		}
		inverses[i] = InvMod(denominator, mod);
	}

	for (int i = 0; i < t; ++i)
	{
		NTL::ZZ li = inverses[i];
		for (int j = 0; j < t; ++j)
		{
			if (i != j)
			{
				li = MulMod(li, neg_xj[j], mod);
			}
		}
		secret = AddMod(secret, MulMod(shares[i].second, li, mod), mod);
	}
	// std::cout<<"recon_res = "<<((secret + mod) % mod)<<std::endl;
	return secret;
}

int reconstruct_secret(const std::vector<int> &selected_indices, const std::vector<std::pair<int, ui128>> &all_shares,
					   std::vector<NTL::ZZ> FourModulo, const NTL::ZZ secret)
{
	std::vector<std::pair<int, ui128>> selected_shares;
	selected_shares.reserve(selected_indices.size());
	for (int index : selected_indices)
	{
		selected_shares.push_back(all_shares[index]);
	}

	std::vector<std::vector<std::pair<NTL::ZZ, NTL::ZZ>>> part(4);
	for (int i = 0; i < part.size(); i++)
	{
		part[i].resize(selected_shares.size());
	}

	for (int i = 0; i < selected_indices.size(); i++)
	{
		for (int j = 0; j < 4; j++)
		{
			u64 shift = (3 - j) * 32;
			part[j][i].first = NTL::ZZ(selected_shares[i].first);
			// part[j][i].second = ((selected_shares[i].second >> ((3-j)*32)) & 0xFFFFFFFF) % FourModulo[j];
			part[j][i].second = AddMod(NTL::ZZ((selected_shares[i].second >> (shift)) & 0xFFFFFFFF), NTL::ZZ(0), FourModulo[j]);
		}
	}

	std::vector<NTL::ZZ> secret_mod(4);

	int flag = 1;
	for (int i = 0; i < 4; i++)
	{
		secret_mod[i] = lagrange_interpolation(part[i], FourModulo[i]);
		{
			if (secret_mod[i] != (secret % FourModulo[i]))
			{
				flag = 0;
			}
		}
	}

	return flag;
}

void get_combinations_iterative(int totalNumShares, int threshold, std::vector<std::vector<int>> &all_combinations)
{
	std::vector<int> current_combination;
	std::vector<int> indices(threshold);

	for (int i = 0; i < threshold; ++i)
	{
		indices[i] = i;
	}

	while (true)
	{

		current_combination.clear();
		for (int i = 0; i < threshold; ++i)
		{
			current_combination.push_back(indices[i]);
		}
		all_combinations.push_back(current_combination);

		int i = threshold - 1;
		while (i >= 0 && indices[i] == totalNumShares - threshold + i)
		{
			--i;
		}
		if (i < 0)
		{
			break;
		}
		++indices[i];
		for (int j = i + 1; j < threshold; ++j)
		{
			indices[j] = indices[j - 1] + 1;
		}
	}
}

template <ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType1>
BOLEReceiverOutput<typename SchemeType1::encoding_context_t::encoding_input_t> ReceiverOnline(
	const BOLEReceiverInput<typename SchemeType1::encoding_context_t::encoding_input_t> &input,
	const typename SchemeType1::SecretKey &sk,
	const SchemeType1 &scheme_origin,
	osuCrypto::Channel &chl)
{

	constexpr ui32 logn_const = logn;

	typedef DCRT_Poly_Ring<params<ui64>, logn_const> PlaintextRing;
	static_assert(std::is_integral<decltype(p)>::value, "p must be an integral constant");

	typedef EncodingContext<PlaintextRing, p> encoding_context_t;
	typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
	typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p> dcrt_params_t;
	typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

	SchemeType scheme(std_dev);
	using scheme_encoding_context_t = typename SchemeType::encoding_context_t;
	using encoding_input_t = typename scheme_encoding_context_t::encoding_input_t;

	// input.send(chl);

	BOLEReceiverOutput<encoding_input_t> output;
	output = BOLEReceiver::online(input, sk, scheme, chl);
	// output.send(chl);
	return output;
}

template <ui64 p, ui32 logn, ui32 numLimbs, typename SchemeType1>
void SenderOnline(
	BOLESenderInput<typename SchemeType1::encoding_context_t::encoding_input_t> &input,
	const typename SchemeType1::PublicKey &pk,
	const SchemeType1 &scheme_origin,
	osuCrypto::Channel &chl)
{
	constexpr ui32 logn_const = logn;

	typedef DCRT_Poly_Ring<params<ui64>, logn_const> PlaintextRing;
	static_assert(std::is_integral<decltype(p)>::value, "p must be an integral constant");

	typedef EncodingContext<PlaintextRing, p> encoding_context_t;
	typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
	typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, p> dcrt_params_t;
	typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

	SchemeType scheme(std_dev);

	using scheme_encoding_context_t = typename SchemeType::encoding_context_t;
	using encoding_input_t = typename scheme_encoding_context_t::encoding_input_t;

	// auto recvIn =  BOLEReceiverInput<encoding_input_t>::receive(chl); //receiver_x
	// BOLEReceiverOutput<encoding_input_t> correct = bole_pt<encoding_context_t>(recvIn, input);  //input:(a,b)

	BOLESender::online(input, pk, scheme, chl);

	// auto bole_output = BOLEReceiverOutput<encoding_input_t>::receive(chl);//receiver_output

	// assert(BOLEReceiverOutput<encoding_input_t>::eq(bole_output, correct));
	// cout << "BOLE computed correct result\n";
}

struct Uint128Hash
{
	std::size_t operator()(const __uint128_t &key) const
	{
		return std::hash<uint64_t>()(static_cast<uint64_t>(key >> 64)) ^ std::hash<uint64_t>()(static_cast<uint64_t>(key));
	}
};

struct Uint128Equal
{
	bool operator()(const __uint128_t &a, const __uint128_t &b) const
	{
		return a == b;
	}
};

template <typename T>
void deep_clear(std::vector<std::vector<T>> &vecvec)
{
	for (auto &v : vecvec)
		std::vector<T>().swap(v);
	std::vector<std::vector<T>>().swap(vecvec);
}

template <typename T>
void release_vector(std::vector<T> &v)
{
	std::vector<T>().swap(v);
}

void syncHelper(u64 myIdx, std::vector<std::vector<osuCrypto::Channel *>> chls)
{
	if (myIdx == chls.size() - 1)
	{
		for (u64 i = 0; i < chls.size() - 1; ++i)
		{
			senderSync(*chls[i][0]);
		}
	}
	else
	{
		recverSync(*chls[chls.size() - 1][0]);
	}
}

void tparty(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 nTrials)
{
	u64 opt = 0;
	std::fstream runtime;
	u64 leaderIdx = nParties - 1; // leader party
	std::vector<u64> mIntersection;
	if (myIdx == 0)
		runtime.open("./runtime_client.txt", runtime.app | runtime.out);

	if (myIdx == leaderIdx)
		runtime.open("./runtime_leader.txt", runtime.app | runtime.out);

#pragma region setup

	double totalTime = 0, totalAvgTime = 0, totalShareTime = 0, totalAvgShareTime = 0, totalReconTime = 0, totalAvgReconTime = 0,
		   totalPhase1Time = 0, totalPhase2Time = 0, totalPhase3Time = 0, totalPhase4Time = 0,
		   totalAvgPhase1Time = 0, totalAvgPhase2Time = 0, totalAvgPhase3Time = 0, totalAvgPhase4Time = 0,
		   totalbaseOTTime = 0, totalAvgbaseOTTime = 0,
		   totalIntersection = 0, totalAvgIntersection = 0;

	std::vector<double> eachTime(nTrials), eachShareTime(nTrials), eachReconTime(nTrials);
	double total_sd = 0, total_share_sd = 0, total_recon_sd = 0;

	u64 totalNumShares = nParties;

	u64 psiSecParam = 40, bitSize = 128, numThreads = 1;
	osuCrypto::PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

	std::string name("psi");
	BtIOService ios(1);

	std::vector<BtEndpoint> ep(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1100 + i * 100 + myIdx;
			;												  // get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); // channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1100 + myIdx * 100 + i;				 // get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); // channel bwt i and pIdx, where i is receiver
		}
	}

	std::vector<std::vector<osuCrypto::Channel *>> chls(nParties);
	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;

		if (i != myIdx)
		{
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				// chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
				// chls[i][j].mEndpoint;
			}
		}
	}
#pragma endregion

	// #pragma region OLEsetup

	//     std::vector<osuCryptoNew::Session> epOLE(nParties);
	//     osuCryptoNew::IOService iosOLE;
	// 	for (u64 i = 0; i < nParties; ++i)
	// 	{
	// 		if (i < myIdx)
	// 		{
	// 			u32 port = 7000 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
	// 			epOLE[i].start(iosOLE, "localhost", port, EpMode::Client, name); //channel bwt i and pIdx, where i is sender
	// 		}
	// 		else if (i > myIdx)
	// 		{
	// 			u32 port = 7000 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
	// 			epOLE[i].start(iosOLE, "localhost", port, EpMode::Server, name); //channel bwt i and pIdx, where i is receiver
	// 		}
	// 	}

	// std::vector<std::vector<osuCryptoNew::Channel>> chlsOLE(nParties);

	//     for (u64 i = 0; i < nParties; ++i)
	// 	{
	// 		//dummy[i] = myIdx * 10 + i;

	// 		if (i != myIdx) {
	// 			chlsOLE[i].resize(numThreads);
	// 			for (u64 j = 0; j < numThreads; ++j)
	// 			{
	// 				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
	// 				chlsOLE[i][j] = epOLE[i].addChannel(name, name);
	// 				//chls[i][j].mEndpoint;
	// 			}
	// 		}
	// 	}
	// #pragma endregion

	// NTL::ZZ sameseed = NTL::conv<NTL::ZZ>("1234");
	// NTL::ZZ diffseed = NTL::ZZ(myIdx);

	u64 num_intersection;
	double dataSent, Mbps, MbpsRecv, dataRecv;
	u64 expected_intersection;

	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
		osuCrypto::Timer timer;
		mIntersection.clear();

#pragma region input

		NTL::ZZ p, intersection;
		NTL::ZZ seed_p = NTL::conv<NTL::ZZ>("2412184378664027336206160438520832671112");
		NTL::SetSeed(seed_p);

		p = NTL::conv<NTL::ZZ>("339933312435546022214350946152556052481");
		NTL::ZZ sameseed = NTL::conv<NTL::ZZ>("1234") + idxTrial;
		NTL::ZZ diffseed = NTL::ZZ(myIdx) + idxTrial;

		std::vector<ui64> FourModulo = {4293230593, 4293836801, 4293918721, 4294475777};
		std::vector<NTL::ZZ> FourModuloZZ;
		for (auto mod : FourModulo)
		{
			FourModuloZZ.push_back(NTL::ZZ(mod));
		}

		NTL::ZZ_p::init(p);

		std::vector<NTL::ZZ> set_zz(setSize);
		std::vector<osuCrypto::block> set(setSize);

		NTL::ZZ element;

		// generate set

		auto generateSet = timer.setTimePoint("generate");

		auto now = std::chrono::high_resolution_clock::now();
		unsigned int seed = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
		seed ^= static_cast<unsigned int>(getpid());
		srand(seed);

		std::string filename = "input/P" + std::to_string(myIdx) + "_" + std::to_string(idxTrial) + ".txt";
		std::remove(filename.c_str());

		std::ofstream outfile(filename);
		std::set<int> party_set;

		if (!outfile)
		{
			std::cerr << "creat file error: " << filename << std::endl;
			exit(1);
		}
		u64 new_element;
		for (int j = 0; j < setSize; j++)
		{
			do
			{
				new_element = rand() % ((nParties / 2) * setSize);
			} while (party_set.find(new_element) != party_set.end());

			party_set.insert(new_element);
			set[j] = osuCrypto::toBlock(new_element);
			set_zz[j] = NTL::conv<NTL::ZZ>(new_element);
			outfile << new_element << std::endl;
		}
		outfile.close();

		syncHelper(myIdx, chls);
		auto setDone = timer.setTimePoint("setDone");

#pragma endregion

		u64 opprfNum = 5 * nParties; // 5 * (nParties - 1)

		std::vector<KkrtNcoOtReceiver> otRecv(opprfNum);
		std::vector<KkrtNcoOtSender> otSend(opprfNum);
		std::vector<OPPRFSender> send(opprfNum);
		std::vector<OPPRFReceiver> recv(opprfNum);

		// ###########################################
		// ### Offline Phasing-secret sharing
		// ###########################################
		// syncHelper(myIdx, chls);
		auto start = timer.setTimePoint("start");

		std::vector<std::vector<std::vector<NTL::ZZ_p>>> shares_zz(4); // shares: 4  * n * setsize
		std::vector<std::vector<std::vector<osuCrypto::block>>>
			sendSSPayLoads(4),
			recvSSPayLoads(4); // 4 * n * setsize

		std::vector<std::vector<NTL::ZZ>> ServerShares(4);
		for (u64 i = 0; i < ServerShares.size(); i++)
		{
			ServerShares[i].resize(setSize);
		}

		for (u64 i = 0; i < recvSSPayLoads.size(); i++)
		{
			recvSSPayLoads[i].resize(totalNumShares);
			sendSSPayLoads[i].resize(totalNumShares);
			for (u64 j = 0; j < recvSSPayLoads[i].size(); j++)
			{
				recvSSPayLoads[i][j].resize(setSize);
				sendSSPayLoads[i][j].resize(setSize);
			}
		}

		if (myIdx == leaderIdx)
		{
			// The leader secretly shares each element x, and each element has a total of n shares.
			NTL::ZZ_p value = NTL::conv<NTL::ZZ_p>(1);
			for (u64 i = 0; i < 4; i++)
			{
				shares_zz[i] = std::vector<std::vector<NTL::ZZ_p>>(totalNumShares, std::vector<NTL::ZZ_p>(setSize)); // 4 * n * setsize
				NTL::ZZ currentModulo = NTL::conv<NTL::ZZ>(FourModulo[i]);

				for (u64 j = 0; j < setSize; j++)
				{
					// std::cout <<"out_value: "<<set_zz[j]<<std::endl;
					NTL::ZZ_p secret = NTL::conv<NTL::ZZ_p>(set_zz[j]);
					// std::cout <<"out_value: "<<secret<<std::endl;
					std::vector<NTL::ZZ_p> secretShares = ShareSecret(secret, totalNumShares, threshold, currentModulo);
					NTL::ZZ_p::init(p);
					// std::cout << "Secret shares for element " << j << " under modulo " << FourModulo[i] << ":\n";

					for (u64 k = 0; k < totalNumShares; k++)
					{
						// std::cout << "Share " << k << ": " << secretShares[k] << "\n";
						shares_zz[i][k][j] = secretShares[k];
					}

					ServerShares[i][j] = NTL::conv<NTL::ZZ>(shares_zz[i][totalNumShares - 1][j]); // end row
				}
			}

			for (u64 i = 0; i < sendSSPayLoads.size(); i++)
			{
				for (u64 j = 0; j < sendSSPayLoads[i].size(); j++)
				{
					for (u64 k = 0; k < sendSSPayLoads[i][j].size(); k++)
					{
						NTL::BytesFromZZ((u8 *)&sendSSPayLoads[i][j][k], NTL::conv<NTL::ZZ>(shares_zz[i][j][k]), sizeof(osuCrypto::block));
						// sendSSPayLoads[i][j][k] = osuCrypto::ZeroBlock;
					}
				}
			}
		}

		binSet bins;
		bins.init(myIdx, nParties, setSize, psiSecParam, opt);

		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();

		// ##########################
		// ### Hashing
		// ##########################

		bins.hashing2Bins(set, 1);
		// syncHelper(myIdx, chls);
		auto hashingDone = timer.setTimePoint("hashingDone");
	

		// std::cout<<"P"<<myIdx<<" hashDone!"<< std::endl;
#pragma OPPRF
		// ##########################
		// ### Base OT
		// ##########################

		if (myIdx == leaderIdx)
		{
			// single thread
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx;
				send[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[thr], otRecv[thr], prng.get<osuCrypto::block>(), false);
			}
		}
		else
		{
			recv[0].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountRecv, otRecv[0], otSend[0], osuCrypto::ZeroBlock, false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx;
				send[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			recv[0].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{

				u64 thr = pIdx;
				send[thr].sendSSTableBased(pIdx, bins, sendSSPayLoads[0][pIdx], chls[pIdx], FourModulo, 0);
			}
		}
		else
		{
			recv[0].recvSSTableBased(leaderIdx, bins, recvSSPayLoads[0][0], chls[leaderIdx], FourModulo, 0);
		}

		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		// 2
		if (myIdx == leaderIdx)
		{
			// single thread
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties;
				send[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[thr], otRecv[thr], prng.get<osuCrypto::block>(), false);
			}
		}
		else
		{
			recv[1].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountRecv, otRecv[1], otSend[1], osuCrypto::ZeroBlock, false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties;
				send[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			recv[1].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{

				u64 thr = pIdx + nParties;
				send[thr].sendSSTableBased(pIdx, bins, sendSSPayLoads[1][pIdx], chls[pIdx], FourModulo, 1);
			}
		}
		else
		{
			recv[1].recvSSTableBased(leaderIdx, bins, recvSSPayLoads[1][0], chls[leaderIdx], FourModulo, 1);
		}

		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		if (myIdx == leaderIdx)
		{
			// single thread
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 2 * nParties;
				send[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[thr], otRecv[thr], prng.get<osuCrypto::block>(), false);
			}
		}
		else
		{
			recv[2].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountRecv, otRecv[2], otSend[2], osuCrypto::ZeroBlock, false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 2 * nParties;
				send[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			recv[2].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{

				u64 thr = pIdx + 2 * nParties;
				send[thr].sendSSTableBased(pIdx, bins, sendSSPayLoads[2][pIdx], chls[pIdx], FourModulo, 2);
			}
		}
		else
		{
			recv[2].recvSSTableBased(leaderIdx, bins, recvSSPayLoads[2][0], chls[leaderIdx], FourModulo, 2);
		}

		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		if (myIdx == leaderIdx)
		{
			// single thread
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 3 * nParties;
				send[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountSend, otSend[thr], otRecv[thr], prng.get<osuCrypto::block>(), false);
			}
		}
		else
		{
			recv[3].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountRecv, otRecv[3], otSend[3], osuCrypto::ZeroBlock, false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 3 * nParties;
				send[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			recv[3].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{

				u64 thr = pIdx + 3 * nParties;
				send[thr].sendSSTableBased(pIdx, bins, sendSSPayLoads[3][pIdx], chls[pIdx], FourModulo, 3);
			}
		}
		else
		{
			recv[3].recvSSTableBased(leaderIdx, bins, recvSSPayLoads[3][0], chls[leaderIdx], FourModulo, 3);
		}

		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

#pragma endregion
		// syncHelper(myIdx, chls);
		auto Phase1Done = timer.setTimePoint("Phase1: secretsharingDone");
		// std::cout << "Party [" << myIdx << "] finish Phase 1." << std::endl;

#pragma region prepare_UpdateValues
		// ###########################################
		// ### generate values and send to others by OLEs ####
		// ###########################################
		u64 UpdateValueSize = bins.mSimpleBins.mBins.size();						 // binNum
		std::vector<std::vector<std::vector<NTL::ZZ_p>>> genUpdateValues(4);		 // 4*UpdateValueSize*totalNumShares
		std::vector<std::vector<std::vector<osuCrypto::block>>> sendUpdateValues(4); // 4 * n * bins.size()
		std::vector<std::vector<std::vector<osuCrypto::block>>> recvUpdateValues(4);
		std::vector<std::vector<std::vector<NTL::ZZ>>> serverUpdateValues(4);
		std::vector<std::vector<osuCrypto::block>> endValues(1);

		for (u64 i = 0; i < recvUpdateValues.size(); i++)
		{
			recvUpdateValues[i].resize(totalNumShares);
			sendUpdateValues[i].resize(totalNumShares);
			for (u64 j = 0; j < recvUpdateValues[i].size(); j++)
			{
				recvUpdateValues[i][j].resize(UpdateValueSize);
				sendUpdateValues[i][j].resize(UpdateValueSize);
			}
		}

		for (u64 i = 0; i < serverUpdateValues.size(); i++)
		{
			serverUpdateValues[i].resize(nParties);
			for (u64 j = 0; j < serverUpdateValues[i].size(); j++)
			{
				serverUpdateValues[i][j].resize(UpdateValueSize);
			}
		}

		for (u64 i = 0; i < endValues.size(); i++)
		{
			endValues[i].resize(UpdateValueSize);
		}

		// each party(except leader) generates values used to update values
		if (myIdx != leaderIdx)
		{
			for (u64 i = 0; i < 4; i++)
			{
				NTL::ZZ currentModulo = NTL::conv<NTL::ZZ>(FourModulo[i]);
				genUpdateValues[i].resize(UpdateValueSize);

				for (u64 j = 0; j < genUpdateValues[i].size(); j++)
				{
					genUpdateValues[i][j].resize(totalNumShares);
					genUpdateValues[i][j] = GenerateUpdateValues(totalNumShares, threshold, currentModulo);
					NTL::ZZ_p::init(p);
				}

				for (u64 j = 0; j < totalNumShares; j++)
				{
					for (u64 k = 0; k < UpdateValueSize; k++)
					{
						NTL::BytesFromZZ((u8 *)&sendUpdateValues[i][j][k], rep((genUpdateValues[i][k][j])), sizeof(osuCrypto::block));
					}
				}
			}
		}

		// each client send values to leader
		if (myIdx != leaderIdx)
		{
			// auto & chl = *chls[leaderIdx][0];
			for (u64 i = 0; i < 4; i++)
			{
				for (u64 j = 0; j < UpdateValueSize; j++) // mbins values
				{
					unsigned char buf[32 / 8];
					NTL::ZZ value = NTL::conv<NTL::ZZ>(genUpdateValues[i][j][totalNumShares - 1]);
					NTL::BytesFromZZ(buf, value, 32 / 8);
					chls[leaderIdx][0]->send(&buf, 32 / 8);
				}
			}
		}
		else
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				// auto & chl = *chls[pIdx][0];
				// chl.recv(recvUpdateValues[pIdx].data(), recvUpdateValues[pIdx].size() * sizeof(block));
				for (u64 i = 0; i < 4; i++)
				{
					for (u64 j = 0; j < UpdateValueSize; j++) // mbins values
					{
						unsigned char buf[32 / 8];
						chls[pIdx][0]->recv(&buf, 32 / 8);
						ZZFromBytes(serverUpdateValues[i][pIdx][j], buf, 32 / 8);
					}
				}
			}
		}

#pragma endregion

#pragma region leader_update
		//*******************************************************
		//************leader updates its shares******************
		//*******************************************************

		if (myIdx == leaderIdx)
		{
			for (u64 i = 0; i < 4; i++)
			{
				NTL::ZZ mod = NTL::conv<NTL::ZZ>(FourModulo[i]);
				for (u64 j = 0; j < nParties - 1; j++)
				{
					for (u64 k = 0; k < UpdateValueSize; k++)
					{
						serverUpdateValues[i][nParties - 1][k] += serverUpdateValues[i][j][k];
						serverUpdateValues[i][nParties - 1][k] %= mod;
					}
				}
			}

			//

			std::vector<std::thread> thrds(1);
			for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
			{
				u64 binStart, binEnd;
				binStart = 0, binEnd = bins.mCuckooBins.mBins.size();
				for (u64 bIdx = binStart; bIdx < binEnd; bIdx++)
				{
					auto &bin = bins.mCuckooBins.mBins[bIdx];
					if (!bin.isEmpty())
					{
						u64 inputIdx = bin.idx();
						// u64 hashIdx = bin.hashIdx();

						// SendValues[0][inputIdx] = SendValues[0][inputIdx] + endValues[bIdx];

						for (u64 i = 0; i < 4; i++)
						{
							NTL::ZZ mod = NTL::conv<NTL::ZZ>(FourModulo[i]);

							NTL::ZZ num1 = ServerShares[i][inputIdx];
							NTL::ZZ num2 = serverUpdateValues[i][nParties - 1][bIdx];

							NTL::ZZ res = AddMod(num1, num2, mod);

							ServerShares[i][inputIdx] = res; // updates shares: 4 * setsize
						}
					}
				}
			}
		}

#pragma endregion

#pragma region OLE
		//*******************************************************
		//**********************OLE Phase************************
		//*******************************************************

		// syncHelper(myIdx, chls);
		auto OLEstart = timer.setTimePoint("OLEstart");
		constexpr ui32 logn = 13;
		const ui32 oleSize = 1 << logn;
		const ui64 up = 4294475777ULL;
		typedef DCRT_Poly_Ring<params<ui64>, logn> PlaintextRing;
		typedef EncodingContext<PlaintextRing, up> encoding_context_t;

		typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
		typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, up> dcrt_params_t;
		typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;

		// leader invokes leaderOleNum OLEs with each client

		u64 leaderOleNum = (nParties - 1) * (bins.mCuckooBins.mBinCount[0] * bins.mCuckooBins.mParams.mSenderBinSize[0] + bins.mCuckooBins.mBinCount[1] * bins.mCuckooBins.mParams.mSenderBinSize[1]);
		// std::cout<<"leaderOleNum: "<< leaderOleNum<<std::endl;
		u64 leaderBoleNum = ceil(leaderOleNum / (oleSize * 1.0));	// bolenum = olenum / 8192 for each client
		std::vector<std::vector<ui128>> leaderInput(leaderBoleNum); // input for each client

		for (u64 i = 0; i < leaderInput.size(); i++)
		{
			leaderInput[i].resize(oleSize);
		}

		std::vector<std::vector<std::vector<ui128>>> randomValue(nParties - 1); // ri :n-1 * 64 * mbins
		std::vector<std::vector<std::vector<ui128>>> partUpValue(nParties - 1); // δi :n-1 * 64 * mbins
		std::vector<std::vector<std::vector<ui128>>> recvOLE(nParties - 1);

		std::vector<std::vector<ui128>> randomValueForLeader(leaderBoleNum); // a
		std::vector<std::vector<ui128>> partUpValueForLeader(leaderBoleNum); // b
		std::vector<std::vector<ui128>> UpdateForLeader(leaderBoleNum);

		std::vector<std::vector<ui128>> ReInput(leaderBoleNum);

		// prepare for OLE
		for (u64 i = 0; i < randomValueForLeader.size(); i++)
		{
			randomValueForLeader[i].resize(oleSize);
			partUpValueForLeader[i].resize(oleSize);
			UpdateForLeader[i].resize(oleSize);
		}

		// prepare random values
		if (myIdx != leaderIdx)
		{
			// each client generates random values for OLE phase size:n-1 * 64 * binsNum
			for (int i = 0; i < nParties - 1; i++)
			{
				randomValue[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
				partUpValue[i].resize(bins.mSimpleBins.mMaxBinSize[1]);

				for (int j = 0; j < bins.mSimpleBins.mMaxBinSize[1]; j++)
				{
					randomValue[i][j].resize(UpdateValueSize);
					partUpValue[i][j].resize(UpdateValueSize);

					for (int k = 0; k < UpdateValueSize; k++)
					{
						NTL::RandomBnd(element, p);
						// element = NTL::ZZ(1);
						NTL::ZZ zz_value = NTL::conv<NTL::ZZ>(element);
						// std::cout<<"randomValue[i][j][k]_ = "<<zz_value<<std::endl;
						randomValue[i][j][k] = ZZ_to_ui128(zz_value);
						// // randomValue[i][j][k] = 1;

						NTL::RandomBnd(element, p);
						// element = NTL::ZZ(0);
						zz_value = NTL::conv<NTL::ZZ>(element);
						// std::cout<<"partUpValue[i][j][k]_ = "<<zz_value<<std::endl;

						partUpValue[i][j][k] = ZZ_to_ui128(zz_value);
					}
				}
			}

			int row = 0, col = 0;
			int count = 0;
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++)
				{
					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else // 64
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (u64 eIdx = 0; eIdx < numMax; eIdx++)
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						randomValueForLeader[row][col] = randomValue[pIdx][eIdx][bIdx];
						partUpValueForLeader[row][col] = partUpValue[pIdx][eIdx][bIdx];
						col++;
					}
				}
			}
		}

		for (int i = 0; i < recvOLE.size(); i++) // n-1 * leaderBoleNum * oleSize
		{
			recvOLE[i].resize(leaderBoleNum);
			for (int j = 0; j < recvOLE[i].size(); j++)
			{
				recvOLE[i][j].resize(oleSize);
			}
		}

		// leader (as OLE receiver) and others invoke OLEs

		auto OLEstart1 = timer.setTimePoint("");
		if (myIdx == leaderIdx)
		{
			int row = 0, col = 0;
			// prepare input[][]
			for (int uIdx = 0; uIdx < nParties - 1; uIdx++)
			{
				NTL::SetSeed(diffseed);
				for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
				{
					auto &bin = bins.mCuckooBins.mBins[bIdx];
					ui128 inputIdx;
					if (!bin.isEmpty())
					{
						inputIdx = block_to_u128(set[bin.idx()]);
						// std::cout<<"bin: "<<inputIdx<<std::endl;
					}
					else
					{
						NTL::RandomBnd(element, p);
						inputIdx = ZZ_to_ui128(element);
						// std::cout<<"input = "<<inputIdx<<std::endl;
						// inputIdx = 0;
					}

					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (int numinBin = 0; numinBin < numMax; numinBin++) // 32 or 64
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						leaderInput[row][col] = inputIdx;
						col++;
					}
				}
			}

			// OLE
			for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				const SchemeType scheme(std_dev);
				auto chl = chls[pIdx][0];
				using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
				using SecretKey = typename SchemeType::SecretKey;

				KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
				sendPublicKey(kpSeeded.pkSeeded, *chl);
				SecretKey &sk = kpSeeded.sk;

				using encoding_context_t = typename SchemeType::encoding_context_t;
				using encoding_input_t = typename encoding_context_t::encoding_input_t;

				for (ui32 i = 0; i < ReInput.size(); i++)
				{
					ReInput[i].resize(oleSize);
					for (ui32 j = 0; j < ReInput[i].size(); j++)
					{
						ui128 input = 0;
						ui128 element = leaderInput[i][j];

						for (ui32 k = 0; k < 4; k++)
						{
							input |= static_cast<ui128>(element) << ((3 - k) * 32);
							// input = input % FourModulo[k];
						}
						ReInput[i][j] = input;
					}
				}

				FourBOLEReceiverInputs<encoding_input_t> FourInputs(leaderBoleNum);
				FourInputs.processModule(ReInput);

				std::vector<BOLEReceiverOutput<encoding_input_t>> FourOutputs(4, BOLEReceiverOutput<encoding_input_t>(FourInputs.receiverInputs[0].numBlocks));

				FourOutputs[0] = ReceiverOnline<4293230593ULL, 13, 4, SchemeType>(
					FourInputs.receiverInputs[0], sk, scheme, *chl);
				FourOutputs[1] = ReceiverOnline<4293836801ULL, 13, 4, SchemeType>(
					FourInputs.receiverInputs[1], sk, scheme, *chl);
				FourOutputs[2] = ReceiverOnline<4293918721ULL, 13, 4, SchemeType>(
					FourInputs.receiverInputs[2], sk, scheme, *chl);
				FourOutputs[3] = ReceiverOnline<4294475777ULL, 13, 4, SchemeType>(
					FourInputs.receiverInputs[3], sk, scheme, *chl);

				for (int BoleIdx = 0; BoleIdx < leaderBoleNum; BoleIdx++)
				{
					for (u64 i = 0; i < oleSize; i++)
					{
						ui128 res = 0;
						for (u64 j = 0; j < 4; j++)
						{
							res |= static_cast<ui128>(FourOutputs[j].cBlocks[BoleIdx][i]) << ((3 - j) * 32);
						}
						recvOLE[pIdx][BoleIdx][i] = res;
					}
				}
			}
		}
		else
		{
			// clients (as OLE Sender) and leader invoke OLEs
			const SchemeType scheme(std_dev);
			auto chl = chls[leaderIdx][0];

			using SeededPublicKey = typename SchemeType::PublicKeySeeded;
			using PublicKey = typename SchemeType::PublicKey;
			SeededPublicKey seededPK;
			receivePublicKey(seededPK, *chl);
			PublicKey pk = seededPK.expand();

			int row = 0, col = 0;

			// prepare update values
			for (int uIdx = 0; uIdx < nParties - 1; uIdx++)
			{
				for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
				{
					ui128 res = 0;
					for (u64 i = 0; i < 4; i++)
					{
						NTL::ZZ part_zz = NTL::ZZFromBytes((u8 *)&sendUpdateValues[i][uIdx][bIdx], sizeof(osuCrypto::block));
						ui128 part = ZZ_to_ui128(part_zz);
						res |= static_cast<ui128>(part) << ((3 - i) * 32);
					}

					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else // 64
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (int numinBin = 0; numinBin < numMax; numinBin++)
					{

						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						UpdateForLeader[row][col] = res;
						col++;
					}
				}
			}

			// invoke OLEs with leader
			using encoding_context_t = typename SchemeType::encoding_context_t;
			using encoding_input_t = typename encoding_context_t::encoding_input_t;

			std::vector<std::vector<encoding_input_t>> aVecs(4);
			std::vector<std::vector<encoding_input_t>> bVecs(4);

			for (ui32 i = 0; i < 4; i++)
			{
				aVecs[i].resize(leaderBoleNum);
				bVecs[i].resize(leaderBoleNum);
				for (ui32 BoleIdx = 0; BoleIdx < leaderBoleNum; BoleIdx++)
				{
					for (ui32 j = 0; j < oleSize; j++)
					{
						u64 shift = (3 - i) * 32;
						aVecs[i][BoleIdx].vals[j] = ((randomValueForLeader[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
						ui128 randnum_a = ((partUpValueForLeader[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
						ui128 randnum_b = ((UpdateForLeader[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];

						bVecs[i][BoleIdx].vals[j] = (randnum_b + FourModulo[i] - randnum_a) % FourModulo[i]; // 需要mod FourModulo[i] 吗？？？？？
					}
				}
			}
			std::vector<BOLESenderInput<encoding_input_t>> FourSenderInput;
			for (ui32 i = 0; i < 4; i++)
			{
				FourSenderInput.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[i], bVecs[i]));
			}
			SenderOnline<4293230593ULL, 13, 4, SchemeType>(FourSenderInput[0], pk, scheme, *chl);
			SenderOnline<4293836801ULL, 13, 4, SchemeType>(FourSenderInput[1], pk, scheme, *chl);
			SenderOnline<4293918721ULL, 13, 4, SchemeType>(FourSenderInput[2], pk, scheme, *chl);
			SenderOnline<4294475777ULL, 13, 4, SchemeType>(FourSenderInput[3], pk, scheme, *chl);
		}

		// syncHelper(myIdx, chls);

		auto OLEend1 = timer.setTimePoint("");
		// std::cout << "Party [" << myIdx << "] finish OLE1 in " << std::chrono::duration_cast<std::chrono::milliseconds>(OLEend1 - OLEstart1).count() << " ms" << std::endl;
		// client and other clients invoke OLEs

		// the number of OLEs between two clients
		u64 ClientOleNum = bins.mSimpleBins.mBinCount[0] * bins.mSimpleBins.mMaxBinSize[0] + bins.mSimpleBins.mBinCount[1] * bins.mSimpleBins.mMaxBinSize[1];
		u64 ClientBoleNum = ceil(ClientOleNum / (1.0 * oleSize));
		// std::cout<<"ClientBoleNum: "<< ClientBoleNum<<std::endl;

		std::vector<std::vector<ui128>> ClientInput_origin(ClientBoleNum);
		std::vector<std::vector<ui128>> ClientInput(ClientBoleNum);

		std::vector<std::vector<ui128>> randomValueForClient(ClientBoleNum);
		std::vector<std::vector<ui128>> partUpValueForClient(ClientBoleNum);
		std::vector<std::vector<ui128>> UpdateForClient(ClientBoleNum);

		for (int i = 0; i < ClientInput_origin.size(); i++)
		{
			ClientInput_origin[i].resize(oleSize);
			ClientInput[i].resize(oleSize);
		}

		for (u64 i = 0; i < randomValueForClient.size(); i++)
		{
			randomValueForClient[i].resize(oleSize);
			partUpValueForClient[i].resize(oleSize);
			UpdateForClient[i].resize(oleSize);
		}

		if (myIdx != leaderIdx)
		{
			u64 row = 0, col = 0;
			NTL::SetSeed(diffseed);

			// prepare client_input[][]
			for (u64 bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mSimpleBins.mBins[bIdx];
				auto eNum = bin.mIdx.size();
				if (eNum > 0)
				{
					for (u64 i = 0; i < eNum; i++)
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						ClientInput_origin[row][col] = block_to_u128(set[bin.mIdx[i]]);
						col++;
					}
				}
				u64 numMax;
				if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
				{
					numMax = bins.mSimpleBins.mMaxBinSize[0];
				}
				else // 64
				{
					numMax = bins.mSimpleBins.mMaxBinSize[1];
				}

				for (u64 i = eNum; i < numMax; i++) // dummy element for OLEs
				{
					if (col >= oleSize)
					{
						row++;
						col = 0;
					}

					NTL::RandomBnd(element, p);
					ClientInput_origin[row][col] = ZZ_to_ui128(element);
					col++;
				}
			}

			for (u64 i = 0; i < ClientInput_origin.size(); i++)
			{
				for (u64 j = 0; j < ClientInput_origin[i].size(); j++)
				{
					ui128 input = 0;
					ui128 element = ClientInput_origin[i][j];
					for (ui32 k = 0; k < 4; k++)
					{
						input |= static_cast<ui128>(element) << ((3 - k) * 32);
					}
					ClientInput[i][j] = input;
				}
			}

			// 	// prepare a(random values) and b(partial values for updating)

			recvOLE.resize(nParties - 1);
			for (int i = 0; i < recvOLE.size(); i++) // n-1 * leaderBoleNum * oleSize
			{
				recvOLE[i].resize(ClientBoleNum);
				for (int j = 0; j < recvOLE[i].size(); j++)
				{
					recvOLE[i][j].resize(oleSize);
				}
			}

			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				// 		//OLE receiver
				if (myIdx > pIdx)
				{
					auto chl = chls[pIdx][0];

					const SchemeType scheme(std_dev);
					using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
					using SecretKey = typename SchemeType::SecretKey;

					KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
					sendPublicKey(kpSeeded.pkSeeded, *chl);
					SecretKey &sk = kpSeeded.sk;

					using encoding_context_t = typename SchemeType::encoding_context_t;
					using encoding_input_t = typename encoding_context_t::encoding_input_t;

					FourBOLEReceiverInputs<encoding_input_t> FourInputs(ClientBoleNum);

					FourInputs.processModule(ClientInput);

					std::vector<BOLEReceiverOutput<encoding_input_t>> FourOutputs(4, BOLEReceiverOutput<encoding_input_t>(FourInputs.receiverInputs[0].numBlocks));

					FourOutputs[0] = ReceiverOnline<4293230593ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[0], sk, scheme, *chl);
					FourOutputs[1] = ReceiverOnline<4293836801ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[1], sk, scheme, *chl);
					FourOutputs[2] = ReceiverOnline<4293918721ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[2], sk, scheme, *chl);
					FourOutputs[3] = ReceiverOnline<4294475777ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[3], sk, scheme, *chl);

					for (int BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++)
					{
						for (u64 i = 0; i < oleSize; i++)
						{
							ui128 res = 0;
							for (u64 j = 0; j < 4; j++)
							{
								res |= static_cast<ui128>(FourOutputs[j].cBlocks[BoleIdx][i]) << ((3 - j) * 32);
							}
							recvOLE[pIdx][BoleIdx][i] = res;
						}
					}
				}
				else if (myIdx < pIdx)
				{
					// 			//prepare a[] b[]  sender
					int row = 0, col = 0;
					auto chl = chls[pIdx][0];
					for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++)
					{
						u64 numMax;
						if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
						{
							numMax = bins.mSimpleBins.mMaxBinSize[0];
						}
						else // 64
						{
							numMax = bins.mSimpleBins.mMaxBinSize[1];
						}

						for (u64 eIdx = 0; eIdx < numMax; eIdx++)
						{
							if (col >= oleSize)
							{
								row++;
								col = 0;
							}
							randomValueForClient[row][col] = randomValue[pIdx][eIdx][bIdx];
							partUpValueForClient[row][col] = partUpValue[pIdx][eIdx][bIdx];
							col++;
						}
					}

					// OLE
					const SchemeType scheme(std_dev);

					using SeededPublicKey = typename SchemeType::PublicKeySeeded;
					using PublicKey = typename SchemeType::PublicKey;
					SeededPublicKey seededPK;
					receivePublicKey(seededPK, *chl);
					PublicKey pk = seededPK.expand();

					using encoding_context_t = typename SchemeType::encoding_context_t;
					using encoding_input_t = typename encoding_context_t::encoding_input_t;

					std::vector<std::vector<encoding_input_t>> aVecs(4);
					std::vector<std::vector<encoding_input_t>> bVecs(4);

					for (ui32 i = 0; i < 4; i++)
					{
						aVecs[i].resize(ClientBoleNum);
						bVecs[i].resize(ClientBoleNum);
						for (ui32 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++)
						{
							for (ui32 j = 0; j < oleSize; j++)
							{
								u64 shift = (3 - i) * 32;
								ui128 randnum = ((randomValueForClient[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
								randnum = FourModulo[i] - randnum;
								aVecs[i][BoleIdx].vals[j] = randnum;

								bVecs[i][BoleIdx].vals[j] = ((partUpValueForClient[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
								// aVecs[i][BoleIdx].vals[j] =
							}
						}
					}

					std::vector<BOLESenderInput<encoding_input_t>> FourSenderInput;
					for (ui32 i = 0; i < 4; i++)
					{
						FourSenderInput.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[i], bVecs[i]));
					}
					SenderOnline<4293230593ULL, 13, 4, SchemeType>(FourSenderInput[0], pk, scheme, *chl);
					SenderOnline<4293836801ULL, 13, 4, SchemeType>(FourSenderInput[1], pk, scheme, *chl);
					SenderOnline<4293918721ULL, 13, 4, SchemeType>(FourSenderInput[2], pk, scheme, *chl);
					SenderOnline<4294475777ULL, 13, 4, SchemeType>(FourSenderInput[3], pk, scheme, *chl);
				}
			}

			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				// 		//OLE receiver
				if (myIdx < pIdx)
				{
					auto chl = chls[pIdx][0];
					// 			//OLE
					SchemeType scheme(std_dev);
					using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
					using SecretKey = typename SchemeType::SecretKey;

					KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
					sendPublicKey(kpSeeded.pkSeeded, *chl);
					SecretKey &sk = kpSeeded.sk;

					using encoding_context_t = typename SchemeType::encoding_context_t;
					using encoding_input_t = typename encoding_context_t::encoding_input_t;

					FourBOLEReceiverInputs<encoding_input_t> FourInputs(ClientBoleNum);
					FourInputs.processModule(ClientInput);

					std::vector<BOLEReceiverOutput<encoding_input_t>> FourOutputs(4, BOLEReceiverOutput<encoding_input_t>(FourInputs.receiverInputs[0].numBlocks));

					FourOutputs[0] = ReceiverOnline<4293230593ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[0], sk, scheme, *chl);
					FourOutputs[1] = ReceiverOnline<4293836801ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[1], sk, scheme, *chl);
					FourOutputs[2] = ReceiverOnline<4293918721ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[2], sk, scheme, *chl);
					FourOutputs[3] = ReceiverOnline<4294475777ULL, 13, 4, SchemeType>(
						FourInputs.receiverInputs[3], sk, scheme, *chl);

					for (int BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++)
					{
						for (u64 i = 0; i < oleSize; i++)
						{
							ui128 res = 0;
							for (u64 j = 0; j < 4; j++)
							{
								res |= static_cast<ui128>(FourOutputs[j].cBlocks[BoleIdx][i]) << ((3 - j) * 32);
							}
							recvOLE[pIdx][BoleIdx][i] = res;
						}
					}
				}
				// 		//OLE sender
				else if (myIdx > pIdx)
				{
					// 			//prepare a[] b[]
					int row = 0, col = 0;
					auto chl = chls[pIdx][0];

					for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++)
					{
						u64 numMax;
						if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
						{
							numMax = bins.mSimpleBins.mMaxBinSize[0];
						}
						else // 64
						{
							numMax = bins.mSimpleBins.mMaxBinSize[1];
						}

						for (u64 eIdx = 0; eIdx < numMax; eIdx++)
						{
							if (col >= oleSize)
							{
								row++;
								col = 0;
							}
							randomValueForClient[row][col] = randomValue[pIdx][eIdx][bIdx];
							partUpValueForClient[row][col] = partUpValue[pIdx][eIdx][bIdx];
							col++;
						}
					}

					// 			//OLE
					const SchemeType scheme(std_dev);

					using SeededPublicKey = typename SchemeType::PublicKeySeeded;
					using PublicKey = typename SchemeType::PublicKey;
					SeededPublicKey seededPK;
					receivePublicKey(seededPK, *chl);
					PublicKey pk = seededPK.expand();

					using encoding_context_t = typename SchemeType::encoding_context_t;
					using encoding_input_t = typename encoding_context_t::encoding_input_t;

					std::vector<std::vector<encoding_input_t>> aVecs(4);
					std::vector<std::vector<encoding_input_t>> bVecs(4);

					for (ui32 i = 0; i < 4; i++)
					{
						aVecs[i].resize(ClientBoleNum);
						bVecs[i].resize(ClientBoleNum);
						for (ui32 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++)
						{
							for (ui32 j = 0; j < oleSize; j++)
							{
								u64 shift = (3 - i) * 32;
								ui128 randnum = ((randomValueForClient[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
								randnum = FourModulo[i] - randnum;
								aVecs[i][BoleIdx].vals[j] = randnum;

								bVecs[i][BoleIdx].vals[j] = ((partUpValueForClient[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
								// aVecs[i][BoleIdx].vals[j] =
							}
						}
					}

					std::vector<BOLESenderInput<encoding_input_t>> FourSenderInput;
					for (ui32 i = 0; i < 4; i++)
					{
						FourSenderInput.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[i], bVecs[i]));
					}
					SenderOnline<4293230593ULL, 13, 4, SchemeType>(FourSenderInput[0], pk, scheme, *chl);
					SenderOnline<4293836801ULL, 13, 4, SchemeType>(FourSenderInput[1], pk, scheme, *chl);
					SenderOnline<4293918721ULL, 13, 4, SchemeType>(FourSenderInput[2], pk, scheme, *chl);
					SenderOnline<4294475777ULL, 13, 4, SchemeType>(FourSenderInput[3], pk, scheme, *chl);
				}
			}
		}

		auto OLEend = timer.setTimePoint("OLEend");
		// std::cout << "Party [" << myIdx << "] finish OLE2 in " << std::chrono::duration_cast<std::chrono::milliseconds>(OLEend - OLEend1).count() << " ms" << std::endl;

		auto OLEtime = std::chrono::duration_cast<std::chrono::milliseconds>(OLEend - OLEstart).count();
		// std::cout << "p" << myIdx << " OLEtime: " << OLEtime / 1000.0 << std::endl;
#pragma endregion

#pragma region Processing OLE results

		std::vector<std::vector<std::vector<ui128>>> OLE_result(nParties - 1);
		for (int i = 0; i < OLE_result.size(); i++)
		{
			OLE_result[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
			for (int j = 0; j < OLE_result[i].size(); j++)
			{
				OLE_result[i][j].resize(bins.mSimpleBins.mBins.size());
			}
		}

		if (myIdx == leaderIdx)
		{

			// Dimension conversion: n-1 * leaderBolenum * olesize --> n-1 * (n-1 * 32/64 * binNum)
			for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				std::vector<std::vector<std::vector<ui128>>> temp(nParties - 1); // n-1*64*binNum

				for (int i = 0; i < temp.size(); i++)
				{
					temp[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
					for (int j = 0; j < temp[i].size(); j++)
					{
						temp[i][j].resize(bins.mSimpleBins.mBins.size());
					}
				}

				int row = 0, col = 0;
				for (int i = 0; i < nParties - 1; i++)
				{
					for (int bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
					{
						u64 numMax;
						if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
						{
							numMax = bins.mSimpleBins.mMaxBinSize[0];
						}
						else // 64
						{
							numMax = bins.mSimpleBins.mMaxBinSize[1];
						}

						for (int j = 0; j < numMax; j++)
						{
							if (col >= oleSize)
							{
								row++;
								col = 0;
							}
							temp[i][j][bIdx] = recvOLE[pIdx][row][col];
							col++;
						}
					}
				}

				for (int i = 0; i < temp.size(); i++)
				{
					for (int j = 0; j < temp[i].size(); j++)
					{
						for (int k = 0; k < temp[i][j].size(); k++)
						{
							// OLE_result[i][j][k] = (ui128)(OLE_result[i][j][k] + temp[i][j][k]) % up;
							std::vector<ui128> part(4);
							std::vector<ui128> addNum(4);
							ui128 res = 0;
							for (int idx = 0; idx < 4; idx++)
							{
								ui128 tempNum;
								u64 shift = (3 - idx) * 32;
								part[idx] = ((OLE_result[i][j][k] >> (shift)) & 0xFFFFFFFF);
								addNum[idx] = ((temp[i][j][k] >> (shift)) & 0xFFFFFFFF);
								tempNum = (part[idx] + addNum[idx]) % FourModulo[idx];
								res |= static_cast<ui128>(tempNum) << (shift);
							}
							OLE_result[i][j][k] = res;
						}
					}
				}
			}
		}
		else
		{

			for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				int row = 0, col = 0;

				for (int bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
				{
					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else // 64
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (int j = 0; j < numMax; j++)
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						OLE_result[pIdx][j][bIdx] = recvOLE[pIdx][row][col];
						col++;
					}
				}
			}

			for (int bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mSimpleBins.mBins[bIdx];
				auto eNum = bin.mIdx.size();

				if (eNum > 0)
				{
					for (u64 i = 0; i < eNum; i++)
					{
						ui128 inputIdx = block_to_u128(set[bin.mIdx[i]]);
						ui128 random = randomValue[myIdx][i][bIdx];
						ui128 partialvalue = partUpValue[myIdx][i][bIdx];

						ui128 res = 0;
						for (u64 idx = 0; idx < 4; idx++)
						{
							u64 shift = (3 - idx) * 32;
							ui128 random_part = ((random >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 partialvalue_part = ((partialvalue >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 temp = (((ui128)FourModulo[idx] - random_part) * inputIdx + partialvalue_part) % FourModulo[idx];
							res |= static_cast<ui128>(temp) << (shift);
						}
						OLE_result[myIdx][i][bIdx] = res;
					}
				}
			}

			for (int i = 1; i < nParties - 1; i++)
			{
				for (int j = 0; j < bins.mSimpleBins.mMaxBinSize[1]; j++)
				{
					for (int k = 0; k < bins.mSimpleBins.mBins.size(); k++)
					{
						// OLE_result[0][j][k] = (ui128)(OLE_result[0][j][k] + OLE_result[i][j][k]) % up;
						ui128 res = 0;
						for (int idx = 0; idx < 4; idx++)
						{
							u64 shift = (3 - idx) * 32;
							ui128 num1 = ((OLE_result[0][j][k] >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 num2 = ((OLE_result[i][j][k] >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 temp = (num1 + num2) % FourModulo[idx];
							res |= static_cast<ui128>(temp) << (shift);
						}
						OLE_result[0][j][k] = res;
					}
				}
			}
		}
#pragma endregion

		// syncHelper(myIdx, chls);
		auto phase2Done = timer.setTimePoint("Phase2: updatesharesDone");
		// std::cout << "Party [" << myIdx << "] finish Phase 2." << std::endl;

// clients send updated secret shares to leader by OPPRF
#pragma region OPPRF

		std::vector<std::vector<osuCrypto::block>> endPayLoads(nParties - 1); // server obtains updated shares from clients
		std::vector<std::vector<std::vector<osuCrypto::block>>> endPayLoads_divide(4);

		for (u64 i = 0; i < endPayLoads.size(); i++)
		{
			endPayLoads[i].resize(setSize);
		}

		for (u64 i = 0; i < endPayLoads_divide.size(); i++)
		{
			endPayLoads_divide[i].resize(nParties - 1);
			for (u64 j = 0; j < endPayLoads_divide[i].size(); j++)
			{
				endPayLoads_divide[i][j].resize(setSize);
			}
		}

		// 1
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx;
				recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], osuCrypto::ZeroBlock, false);
			}
		}
		else
		{
			send[0].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[0], otRecv[0], prng.get<osuCrypto::block>(), false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx;
				recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			send[0].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx;
				recv[thr].recvSSTableBased(pIdx, bins, endPayLoads_divide[0][pIdx], chls[pIdx], FourModulo, 0);
			}
		}
		else
		{
			send[0].sendSSTableBased(leaderIdx, bins, recvSSPayLoads[0][0], OLE_result[0], chls[leaderIdx], FourModulo, 0);
		}

		// reset bins
		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		// 2
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties;
				recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], osuCrypto::ZeroBlock, false);
			}
		}
		else
		{
			send[1].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[1], otRecv[1], prng.get<osuCrypto::block>(), false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties;
				recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			send[1].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + nParties;
				recv[thr].recvSSTableBased(pIdx, bins, endPayLoads_divide[1][pIdx], chls[pIdx], FourModulo, 1);
			}
		}
		else
		{
			send[1].sendSSTableBased(leaderIdx, bins, recvSSPayLoads[1][0], OLE_result[0], chls[leaderIdx], FourModulo, 1);
		}

		// reset bins
		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		// 3
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 2 * nParties;
				recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], osuCrypto::ZeroBlock, false);
			}
		}
		else
		{
			send[2].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[2], otRecv[2], prng.get<osuCrypto::block>(), false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 2 * nParties;
				recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			send[2].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 2 * nParties;
				recv[thr].recvSSTableBased(pIdx, bins, endPayLoads_divide[2][pIdx], chls[pIdx], FourModulo, 2);
			}
		}
		else
		{
			send[2].sendSSTableBased(leaderIdx, bins, recvSSPayLoads[2][0], OLE_result[0], chls[leaderIdx], FourModulo, 2);
		}

		// reset bins
		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		// 4
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 3 * nParties;
				recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], osuCrypto::ZeroBlock, false);
			}
		}
		else
		{
			send[3].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[3], otRecv[3], prng.get<osuCrypto::block>(), false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 3 * nParties;
				recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			send[3].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 3 * nParties;
				recv[thr].recvSSTableBased(pIdx, bins, endPayLoads_divide[3][pIdx], chls[pIdx], FourModulo, 3);
			}
		}
		else
		{
			send[3].sendSSTableBased(leaderIdx, bins, recvSSPayLoads[3][0], OLE_result[0], chls[leaderIdx], FourModulo, 3);
		}

		// reset bins
		for (int i = 0; i < bins.mSimpleBins.mBins.size(); i++)
		{
			for (u64 j = 0; j < bins.mSimpleBins.mBins[i].mBits.size(); j++)
			{
				bins.mSimpleBins.mBins[i].mBits[j].mPos = {};
				bins.mSimpleBins.mBins[i].mBits[j].mMaps = {};
			}
		}

		if (myIdx == leaderIdx)
		{
			for (u64 i = 0; i < endPayLoads.size(); i++)
			{
				for (u64 j = 0; j < endPayLoads[i].size(); j++)
				{
					u128 res = 0;
					for (u64 idx = 0; idx < 4; idx++)
					{
						u128 conver_value = block_to_u128(endPayLoads_divide[idx][i][j]);
						u128 temp = (conver_value & 0xFFFFFFFF);
						res |= static_cast<u128>(temp) << ((3 - idx) * 32);
					}
					endPayLoads[i][j] = u128_to_block(res);
				}
			}
		}

// 		auto test1 = timer.setTimePoint("test");
#pragma endregion

// clients send OLE index to leader
#pragma region send_OLE_index

		std::vector<std::vector<osuCrypto::block>> OleIndex(nParties - 1);
		for (u64 i = 0; i < OleIndex.size(); i++)
		{
			OleIndex[i].resize(setSize);
		}

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 4 * nParties;
				recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], osuCrypto::ZeroBlock, false);
			}
		}
		else
		{
			send[4].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[4], otRecv[4], prng.get<osuCrypto::block>(), false);
		}

		// 		//OPRF
		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 4 * nParties;
				recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
			}
		}
		else
		{
			send[4].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
		}

		// OPPRF

		if (myIdx == leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				u64 thr = pIdx + 4 * nParties;
				recv[thr].recvSSTableBased(pIdx, bins, OleIndex[pIdx], chls[pIdx]);
			}
		}
		else
		{
			send[4].sendSSTableBased(leaderIdx, bins, chls[leaderIdx]);
		}

		// 		auto test2 = timer.setTimePoint("test");

#pragma endregion

#pragma region leader process data

		std::vector<std::vector<ui128>> endShares(totalNumShares); // contains updated shares of each party n * setsize
		std::vector<std::vector<ui128>> leader_recv_value(4);

		if (myIdx == leaderIdx)
		{

			for (int i = 0; i < endShares.size(); i++)
			{
				endShares[i].resize(setSize);
			}

			// process clients' shares
			for (int bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mCuckooBins.mBins[bIdx];
				if (!bin.isEmpty())
				{
					u64 inputIdx = bin.idx();
					for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
					{
						osuCrypto::block recv_value = endPayLoads[pIdx][inputIdx];
						ui128 recv_value_128 = block_to_u128(recv_value); // client pidx updated share

						ui128 index = block_to_u128(OleIndex[pIdx][inputIdx]);
						index = index & 0x3F; //

						ui128 value1 = OLE_result[pIdx][index][bIdx];
						ui128 value2 = recv_value_128;

						ui128 res = 0;
						for (int idx = 0; idx < 4; idx++)
						{
							u64 shift = (3 - idx) * 32;
							ui128 num1 = ((value1 >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 num2 = ((value2 >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 temp = (num1 + num2) % FourModulo[idx];
							res |= static_cast<ui128>(temp) << (shift);

							// boost::multiprecision::uint256_t pp= res;
							// std::cout<<pp<<std::endl;
						}
						endShares[pIdx][inputIdx] = res; // clients' updated shares
					}
				}
			}

			// leader's shares

			for (u64 i = 0; i < setSize; i++)
			{
				ui128 res = 0;
				for (u64 idx = 0; idx < 4; idx++)
				{
					u64 shift = (3 - idx) * 32;
					ui128 value = ZZ_to_ui128(ServerShares[idx][i]);
					res |= static_cast<ui128>(value) << (shift);
				}
				endShares[nParties - 1][i] = res;
			}
		}

#pragma endregion
		// syncHelper(myIdx, chls);
		auto phase3Done = timer.setTimePoint("Phase3: collectsharesDone");
		// std::cout << "Party [" << myIdx << "] finish Phase 3." << std::endl;

#pragma region Intersection

		// std::vector<std::vector<ui128>> updated_shares(setSize);
		std::vector<std::vector<std::pair<int, ui128>>> endShares_T(setSize);

		std::unordered_set<u64> result;

		if (myIdx == leaderIdx)
		{
			for (u64 i = 0; i < endShares_T.size(); i++)
			{
				// updated_shares[i].resize(totalNumShares);
				endShares_T[i].resize(totalNumShares);
				for (u64 j = 0; j < totalNumShares; j++)
				{
					endShares_T[i][j].first = j + 1;
					endShares_T[i][j].second = endShares[j][i];
					// endShares_T[i][j].second = block_to_u128(sendSSPayLoads[j][i]);
				}
			}
			std::vector<std::vector<int>> all_combinations;
			get_combinations_iterative(totalNumShares - 1, threshold - 1, all_combinations);

			for (int i = 0; i < all_combinations.size(); i++)
			{
				all_combinations[i].push_back(leaderIdx);
			}

			for (int eIdx = 0; eIdx < setSize; eIdx++)
			{
				for (const auto &current_combination : all_combinations)
				{
					int res = reconstruct_secret(current_combination, endShares_T[eIdx], FourModuloZZ, set_zz[eIdx]);
					if (res == 1)
					{
						// std::cout<<set_zz[eIdx]<<std::endl;
						result.insert(eIdx);
						break;
					}
				}
			}
		}

		auto getIntersection = timer.setTimePoint("getIntersection");

		if (myIdx == leaderIdx)
		{
			std::unordered_map<std::string, std::unordered_set<std::string>> element_to_parties;
			const char *dir_path = "./input";
			DIR *dir = opendir(dir_path);
			if (dir == NULL)
			{
				perror("opendir error");
				exit(-1);
			}
			struct dirent *entry;
			std::string leader = "P" + std::to_string(leaderIdx) + "_" + std::to_string(idxTrial) + ".txt";
			std::vector<std::string> element_files(nParties);
			for (int i = 0; i < element_files.size(); i++)
			{
				element_files[i] = "P" + std::to_string(i) + "_" + std::to_string(idxTrial) + ".txt";
			}
			while ((entry = readdir(dir)) != NULL)
			{
				std::string filename = entry->d_name;

				if (std::find(element_files.begin(), element_files.end(), std::string(filename)) != element_files.end())
				{

					std::string file_path = std::string(dir_path) + "/" + filename;

					std::ifstream file(file_path);

					if (!file.is_open())
					{
						std::cerr << "Failed to open file: " << file_path << std::endl;
						continue;
					}

					std::string element;
					while (getline(file, element))
					{
						element_to_parties[element].insert(filename);
					}

					// std::remove(file_path.c_str());
				}
			}

			closedir(dir);

			int count = 0;

			for (const auto &pair : element_to_parties)
			{
				if (pair.second.size() >= threshold && pair.second.count(leader) > 0)
				{
					count++;
				}
			}
			expected_intersection = count;
			std::cout << "the number of intersection is " << result.size() << std::endl;
			std::cout << "the number of expected_intersection is " << expected_intersection << std::endl;
		}
#pragma endregion

		if (myIdx == 0 || myIdx == leaderIdx)
		{
			auto phase1 = std::chrono::duration_cast<std::chrono::milliseconds>(Phase1Done - hashingDone).count();	   // secret sharing + opprf
			auto phase2 = std::chrono::duration_cast<std::chrono::milliseconds>(phase2Done - Phase1Done).count();	   // update share(OLE)
			auto phase3 = std::chrono::duration_cast<std::chrono::milliseconds>(phase3Done - phase2Done).count();	   // OPPRF
			auto phase4 = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - phase3Done).count(); // reconstruction

			// auto test1_time = std::chrono::duration_cast<std::chrono::milliseconds>(test1 - phase2Done).count();
			// auto test2_time = std::chrono::duration_cast<std::chrono::milliseconds>(test2 - test1).count();

			// auto leader_Ole = std::chrono::duration_cast<std::chrono::milliseconds>(OLEend1 - OLEstart1).count();

			double time = phase1 + phase2 + phase3 + phase4;
			double share_time = phase1 + phase2 + phase3;
			double recon_time = phase4;

			time /= 1000;
			share_time /= 1000;
			recon_time /= 1000;

			eachTime[idxTrial] = time; // s
			eachShareTime[idxTrial] = share_time;
			eachReconTime[idxTrial] = recon_time;

			dataSent = 0;
			dataRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;
			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx)
				{
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dataRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataRecv * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx)
				{
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}

			if (myIdx == leaderIdx)
			{
				// osuCrypto::Log::out << "#Output Intersection: " << result.size() << osuCrypto::Log::endl;
				// osuCrypto::Log::out << "#Expected Intersection: " << expected_intersection << osuCrypto::Log::endl;
				num_intersection = result.size();
				std::string filename = "time_leader.txt";
				std::ofstream oFile;
				oFile.open(filename, std::ios::out | std::ios::app);
				oFile << "numParty: " << nParties << " "
					  << "threshold: " << threshold << " "
					  << "setSize: " << setSize << "\n"
					  << "Expected Intersection: " << expected_intersection << "\n"
					  << "Output Intersection: " << result.size() << "\n"
					  << "Phase1 time: " << phase1 << " ms\n"
					  << "Phase2 time: " << phase2 << " ms\n"
					  // <<"OPPRF1 time: " << test1_time<< " ms\n"
					  // <<"OPPRF2 time: " << test2_time<< " ms\n"
					  // <<"leaderOLE time: " << leader_Ole<< " ms\n"
					  << "Phase3 time: " << phase3 << " ms\n"
					  << "Phase4 time: " << phase4 << " ms\n"
					  << "share time: " << share_time << " s\n"
					  << "recon time: " << recon_time << " s\n"
					  << "Total time: " << time << " s\n"
					  << "------------------\n";
			}

			// std::cout
			// 	<< "Total time: " << time << " s\n"

			// 	<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			// 	<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			// 	<< "------------------\n";
			std::cout << "setSize: " << setSize << "\n"
					  << "Phase1 time: " << phase1 << " ms\n"
					  << "Phase2 time: " << phase2 << " ms\n"
					  << "Phase3 time: " << phase3 << " ms\n"
					  << "Phase4 time: " << phase4 << " ms\n"
					  << "share time: " << share_time << " ms\n"
					  << "recon time: " << recon_time << " ms\n"
					  << "Total time: " << time << " s\n"

					  << "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
					  << "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
					  << "------------------\n";

			totalTime += time;
			totalShareTime += share_time;
			totalReconTime += recon_time;
			totalPhase1Time += phase1;
			totalPhase2Time += phase2;
			totalPhase3Time += phase3;
			totalPhase4Time += phase4;
		}

		deep_clear(shares_zz);
		deep_clear(ServerShares);
		deep_clear(genUpdateValues);
		deep_clear(sendUpdateValues);
		deep_clear(recvUpdateValues);
		deep_clear(serverUpdateValues);
		deep_clear(endValues);
		deep_clear(leaderInput);
		deep_clear(randomValue);
		deep_clear(partUpValue);
		deep_clear(recvOLE);
		deep_clear(randomValueForLeader);
		deep_clear(partUpValueForLeader);
		deep_clear(UpdateForLeader);
		deep_clear(ReInput);
		deep_clear(ClientInput_origin);
		deep_clear(ClientInput);
		deep_clear(randomValueForClient);
		deep_clear(partUpValueForClient);
		deep_clear(UpdateForClient);
		deep_clear(OLE_result);
		deep_clear(endPayLoads);
		deep_clear(OleIndex);
		deep_clear(endShares);
		deep_clear(leader_recv_value);
		deep_clear(endShares_T);

		release_vector(FourModulo);
		release_vector(FourModuloZZ);
		release_vector(set_zz);
		release_vector(set);
		release_vector(otRecv);
		release_vector(otSend);
		release_vector(send);
		release_vector(recv);

		std::unordered_set<u64>().swap(result);
	}

	std::cout << osuCrypto::IoStream::lock;
	if (myIdx == 0 || myIdx == leaderIdx)
	{
		totalAvgTime = totalTime / nTrials;
		totalAvgShareTime = totalShareTime / nTrials;
		totalAvgReconTime = totalReconTime / nTrials;
		totalAvgPhase1Time = totalPhase1Time / nTrials;
		totalAvgPhase2Time = totalPhase2Time / nTrials;
		totalAvgPhase3Time = totalPhase3Time / nTrials;
		totalAvgPhase4Time = totalPhase4Time / nTrials;

		for (u64 i = 0; i < nTrials; i++)
		{
			total_sd += pow(eachTime[i] - totalAvgTime, 2);
			total_share_sd += pow(eachShareTime[i] - totalAvgShareTime, 2);
			total_recon_sd += pow(eachReconTime[i] - totalAvgReconTime, 2);
		}

		total_sd = sqrt(total_sd / nTrials);
		total_share_sd = sqrt(total_share_sd / nTrials);
		total_recon_sd = sqrt(total_recon_sd / nTrials);

		std::cout << "=========avg==========\n";
		runtime << "=========avg==========\n";
		runtime << "numParty: " << nParties
				<< "  threshold: " << threshold
				<< "  setSize: " << setSize
				<< "  nTrials:" << nTrials << "\n";

		if (myIdx == 0)
		{
			std::cout << "Client Idx: " << myIdx << "\n";
			runtime << "Client Idx: " << myIdx << "\n";
		}
		else
		{
			std::cout << "Leader Idx: " << myIdx << "\n";
			osuCrypto::Log::out << "#Output Intersection: " << num_intersection << osuCrypto::Log::endl;
			osuCrypto::Log::out << "#Expected Intersection: " << expected_intersection << osuCrypto::Log::endl;

			runtime << "Leader Idx: " << myIdx << "\n";
			runtime << "#Output Intersection: " << num_intersection << "\n";
			runtime << "#Expected Intersection: " << expected_intersection << "\n";

			std::string filename = "time_leader.txt";
			std::ofstream oFile;
			oFile.open(filename, std::ios::out | std::ios::app);
			oFile << "************************************* \n"
				  << "numParty: " << nParties << " "
				  << "threshold: " << threshold << " "
				  << "setSize: " << setSize << "\n"
				  << "share time: " << totalAvgShareTime << " s\n"
				  << "total_share_sd: " << total_share_sd << " s\n"
				  << "recon time: " << totalAvgReconTime << " s\n"
				  << "total_recon_sd: " << total_recon_sd << " s\n"
				  << "Total time: " << totalAvgTime << " s\n"
				  << "total_sd: " << total_sd << " s\n"
				  << "------------------\n";
		}

		std::cout << "numParty: " << nParties
				  << "  threshold: " << threshold
				  << "  setSize: " << setSize
				  << "  nTrials:" << nTrials << "\n"

				  << "Total time: " << totalAvgTime << " s\n"
				  // << "total_sd: " << total_sd << " s\n"

				  << "share time: " << totalAvgShareTime << " s\n"
				  // <<"total_share_sd: " << total_share_sd<< " s\n"

				  << "recon time: " << totalAvgReconTime << " s\n"
				  // << "total_recon_sd: "<< total_recon_sd<< " s\n"

				  << "phase1 time: " << totalAvgPhase1Time << " ms\n"
				  << "phase2 time: " << totalAvgPhase2Time << " ms\n"
				  << "phase3 time: " << totalAvgPhase3Time << " ms\n"
				  << "phase4 time: " << totalAvgPhase4Time << " ms\n"
				  << "------------------\n";

		runtime << "numParty: " << nParties
				<< "  threshold: " << threshold
				<< "  setSize: " << setSize
				<< "  nTrials:" << nTrials << "\n"

				<< "Total time: " << totalAvgTime << " s\n"
				// << "total_sd: " << total_sd << " s\n"

				<< "share time: " << totalAvgShareTime << " s\n"
				// <<"total_share_sd: " << total_share_sd<< " s\n"

				<< "recon time: " << totalAvgReconTime << " s\n"
				// << "total_recon_sd: "<< total_recon_sd<< " s\n"
				<< "phase1 time: " << totalAvgPhase1Time << " ms\n"
				<< "phase2 time: " << totalAvgPhase2Time << " ms\n"
				<< "phase3 time: " << totalAvgPhase3Time << " ms\n"
				<< "phase4 time: " << totalAvgPhase4Time << " ms\n"
				<< "------------------\n";

		runtime.close();
	}

	// for (u64 i = 0; i < nParties; ++i)
	// {
	// 	if (i != myIdx)
	// 	{
	// 		for (u64 j = 0; j < numThreads; ++j)
	// 		{
	// 			chlsOLE[i][j].close();
	// 		}
	// 	}
	// }
	// //  std::cout<<"Idx = " << myIdx <<" 111"<< std::endl;
	// for (u64 i = 0; i < nParties; ++i)
	// {
	// 	if (i != myIdx)
	// 		epOLE[i].stop();
	// }

	// iosOLE.stop();

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}

	ios.stop();
}

// 简单并行助手：对 pIdx ∈ [0, nParties-2] 并行执行 fn(pIdx)
template <typename Fn>
inline void for_each_party_parallel(u64 nPartiesMinus1, Fn &&fn)
{
	std::vector<std::thread> ts;
	ts.reserve(nPartiesMinus1);
	for (u64 pIdx = 0; pIdx < nPartiesMinus1; ++pIdx)
	{
		ts.emplace_back([&, pIdx]
						{ fn(pIdx); });
	}
	for (auto &t : ts)
		t.join();
}

// ============================================
// =========== 多线程版本：tparty_mt ===========
// ============================================
void tparty_mt(u64 myIdx, u64 nParties, u64 threshold, u64 setSize, u64 nTrials)
{
	u64 opt = 0;
	std::fstream runtime;
	u64 leaderIdx = nParties - 1; // leader party
	std::vector<u64> mIntersection;
	if (myIdx == 0)
		runtime.open("./runtime_client_MT.txt", runtime.app | runtime.out);

	if (myIdx == leaderIdx)
		runtime.open("./runtime_leader_MT.txt", runtime.app | runtime.out);

#pragma region setup
	double totalTime = 0, totalAvgTime = 0, totalShareTime = 0, totalAvgShareTime = 0, totalReconTime = 0, totalAvgReconTime = 0,
		   totalPhase1Time = 0, totalPhase2Time = 0, totalPhase3Time = 0, totalPhase4Time = 0,
		   totalAvgPhase1Time = 0, totalAvgPhase2Time = 0, totalAvgPhase3Time = 0, totalAvgPhase4Time = 0,
		   totalbaseOTTime = 0, totalAvgbaseOTTime = 0;

	std::vector<double> eachTime(nTrials), eachShareTime(nTrials), eachReconTime(nTrials);
	double total_sd = 0, total_share_sd = 0, total_recon_sd = 0;

	u64 totalNumShares = nParties;

	u64 psiSecParam = 40, bitSize = 128, numThreads = 1;
	osuCrypto::PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

	std::string name("psi");
	u64 x = 1;
	if (myIdx == leaderIdx)
	{
		x = nParties - 1;
	}
	BtIOService ios(x);

	std::vector<BtEndpoint> ep(nParties);
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1100 + i * 100 + myIdx;
			;												  // get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); // channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1100 + myIdx * 100 + i;				 // get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); // channel bwt i and pIdx, where i is receiver
		}
	}

	std::vector<std::vector<osuCrypto::Channel *>> chls(nParties);
	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;

		if (i != myIdx)
		{
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				// chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
				// chls[i][j].mEndpoint;
			}
		}
	}
#pragma endregion

	// #pragma region OLEsetup

	// 	std::vector<osuCryptoNew::Session> epOLE(nParties);
	// 	osuCryptoNew::IOService iosOLE;
	// 	for (u64 i = 0; i < nParties; ++i)
	// 	{
	// 		if (i < myIdx)
	// 		{
	// 			u32 port = 7000 + i * 100 + myIdx;
	// 			;																 // get the same port; i=1 & pIdx=2 =>port=102
	// 			epOLE[i].start(iosOLE, "localhost", port, EpMode::Client, name); // channel bwt i and pIdx, where i is sender
	// 		}
	// 		else if (i > myIdx)
	// 		{
	// 			u32 port = 7000 + myIdx * 100 + i;								 // get the same port; i=2 & pIdx=1 =>port=102
	// 			epOLE[i].start(iosOLE, "localhost", port, EpMode::Server, name); // channel bwt i and pIdx, where i is receiver
	// 		}
	// 	}

	// 	std::vector<std::vector<osuCryptoNew::Channel>> chlsOLE(nParties);

	// 	for (u64 i = 0; i < nParties; ++i)
	// 	{
	// 		// dummy[i] = myIdx * 10 + i;

	// 		if (i != myIdx)
	// 		{
	// 			chlsOLE[i].resize(numThreads);
	// 			for (u64 j = 0; j < numThreads; ++j)
	// 			{
	// 				// chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
	// 				chlsOLE[i][j] = epOLE[i].addChannel(name, name);
	// 				// chls[i][j].mEndpoint;
	// 			}
	// 		}
	// 	}
	// #pragma endregion

	u64 num_intersection;
	double dataSent, Mbps, MbpsRecv, dataRecv;
	u64 expected_intersection;

	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
		osuCrypto::Timer timer;
		mIntersection.clear();

#pragma region input
		NTL::ZZ p, intersection;
		NTL::ZZ seed_p = NTL::conv<NTL::ZZ>("2412184378664027336206160438520832671112");
		NTL::SetSeed(seed_p);
		p = NTL::conv<NTL::ZZ>("339933312435546022214350946152556052481");

		NTL::ZZ sameseed = NTL::conv<NTL::ZZ>("1234") + idxTrial;
		NTL::ZZ diffseed = NTL::ZZ(myIdx) + idxTrial;

		std::vector<ui64> FourModulo = {4293230593, 4293836801, 4293918721, 4294475777};
		std::vector<NTL::ZZ> FourModuloZZ;
		FourModuloZZ.reserve(4);
		for (auto mod : FourModulo)
			FourModuloZZ.push_back(NTL::ZZ(mod));

		NTL::ZZ_p::init(p);

		std::vector<NTL::ZZ> set_zz(setSize);
		std::vector<osuCrypto::block> set(setSize);
		NTL::ZZ element;

		auto generateSet = timer.setTimePoint("generate");
		auto now = std::chrono::high_resolution_clock::now();
		unsigned int seed = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
		seed ^= static_cast<unsigned int>(getpid());
		srand(seed);

		std::string filename = "input/P" + std::to_string(myIdx) + "_" + std::to_string(idxTrial) + ".txt";
		std::remove(filename.c_str());
		std::ofstream outfile(filename);
		std::set<int> party_set;

		if (!outfile)
		{
			std::cerr << "creat file error: " << filename << std::endl;
			exit(1);
		}
		u64 new_element;
		for (int j = 0; j < setSize; j++)
		{
			do
			{
				// new_element = rand() % ((nParties / 2) * setSize);
				new_element = rand() % (2 * setSize);
			} while (party_set.find(new_element) != party_set.end());

			party_set.insert(new_element);
			set[j] = osuCrypto::toBlock(new_element);
			set_zz[j] = NTL::conv<NTL::ZZ>(new_element);
			outfile << new_element << std::endl;
		}
		outfile.close();

		syncHelper(myIdx, chls);
		auto setDone = timer.setTimePoint("setDone");
#pragma endregion

		u64 opprfNum = 5 * nParties; // 5 * (nParties - 1)
		std::vector<KkrtNcoOtReceiver> otRecv(opprfNum);
		std::vector<KkrtNcoOtSender> otSend(opprfNum);
		std::vector<OPPRFSender> send(opprfNum);
		std::vector<OPPRFReceiver> recv(opprfNum);

		// ###########################################
		// ### Offline Phasing-secret sharing
		// ###########################################
		// syncHelper(myIdx, chls);
		auto start = timer.setTimePoint("start");

		std::vector<std::vector<std::vector<NTL::ZZ_p>>> shares_zz(4); // shares: 4  * n * setsize
		std::vector<std::vector<std::vector<osuCrypto::block>>> sendSSPayLoads(4), recvSSPayLoads(4);

		std::vector<std::vector<NTL::ZZ>> ServerShares(4);
		for (u64 i = 0; i < ServerShares.size(); i++)
		{
			ServerShares[i].resize(setSize);
		}

		for (u64 i = 0; i < recvSSPayLoads.size(); i++)
		{
			recvSSPayLoads[i].resize(totalNumShares);
			sendSSPayLoads[i].resize(totalNumShares);
			for (u64 j = 0; j < recvSSPayLoads[i].size(); j++)
			{
				recvSSPayLoads[i][j].resize(setSize);
				sendSSPayLoads[i][j].resize(setSize);
			}
		}

		if (myIdx == leaderIdx)
		{
			// The leader secretly shares each element x, and each element has a total of n shares.
			NTL::ZZ_p value = NTL::conv<NTL::ZZ_p>(1);
			for (u64 i = 0; i < 4; i++)
			{
				shares_zz[i] = std::vector<std::vector<NTL::ZZ_p>>(totalNumShares, std::vector<NTL::ZZ_p>(setSize)); // 4 * n * setsize
				NTL::ZZ currentModulo = NTL::conv<NTL::ZZ>(FourModulo[i]);

				for (u64 j = 0; j < setSize; j++)
				{
					// std::cout <<"out_value: "<<set_zz[j]<<std::endl;
					NTL::ZZ_p secret = NTL::conv<NTL::ZZ_p>(set_zz[j]);
					// std::cout <<"out_value: "<<secret<<std::endl;
					std::vector<NTL::ZZ_p> secretShares = ShareSecret(secret, totalNumShares, threshold, currentModulo);
					NTL::ZZ_p::init(p);
					// std::cout << "Secret shares for element " << j << " under modulo " << FourModulo[i] << ":\n";

					for (u64 k = 0; k < totalNumShares; k++)
					{
						// std::cout << "Share " << k << ": " << secretShares[k] << "\n";
						shares_zz[i][k][j] = secretShares[k];
					}

					ServerShares[i][j] = NTL::conv<NTL::ZZ>(shares_zz[i][totalNumShares - 1][j]); // end row
				}
			}

			for (u64 i = 0; i < sendSSPayLoads.size(); i++)
			{
				for (u64 j = 0; j < sendSSPayLoads[i].size(); j++)
				{
					for (u64 k = 0; k < sendSSPayLoads[i][j].size(); k++)
					{
						NTL::BytesFromZZ((u8 *)&sendSSPayLoads[i][j][k], NTL::conv<NTL::ZZ>(shares_zz[i][j][k]), sizeof(osuCrypto::block));
						// sendSSPayLoads[i][j][k] = osuCrypto::ZeroBlock;
					}
				}
			}
		}

		std::vector<osuCrypto::binSet> binsVec(5);

		std::vector<std::thread> workers;
		workers.reserve(5);
		for (u64 r = 0; r < 5; ++r)
		{
			workers.emplace_back([&, r]()
								 {
			binsVec[r].init(myIdx, nParties, setSize, psiSecParam, opt);

			binsVec[r].hashing2Bins(set, 1); });
		}
		for (auto &t : workers)
			t.join();

		binSet &bins = binsVec[0];
		// bins.init(myIdx, nParties, setSize, psiSecParam, opt);

		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();

		// ##########################
		// ### Hashing
		// ##########################
		// bins.hashing2Bins(set, 1);

		// syncHelper(myIdx, chls);
		auto hashingDone = timer.setTimePoint("hashingDone");



#pragma OPPRF
		// ##########################
		// ### Base OT
		// ##########################

		if (myIdx == leaderIdx)
		{
			// leader 端并行
			std::vector<std::thread> workers;
			workers.reserve(nParties - 1);

			for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
			{
				workers.emplace_back([&, pIdx]()
									 {
						for (u64 r = 0; r < 4; ++r)
						{
						const u64 thr = pIdx + r * nParties; // 每轮的正确索引
						auto opprfleaderstart = timer.setTimePoint("opprfleaderstart");
						send[thr].init(
							opt, nParties, setSize, psiSecParam, bitSize,
							chls[pIdx], otCountSend, otSend[thr], otRecv[thr],
							prng.get<osuCrypto::block>(),  false
						);
				
						send[thr].getOPRFkeys(pIdx, binsVec[r], chls[pIdx], false);
					
						send[thr].sendSSTableBased(
							pIdx, binsVec[r], sendSSPayLoads[r][pIdx], chls[pIdx], FourModulo, r
						);
						

					} });
			}
			for (auto &t : workers)
				t.join();
		}
		else
		{
			for (u64 r = 0; r < 4; ++r)
			{
				auto opprfclientstart = timer.setTimePoint("opprfclientstart");
				const u64 thr = r;
				recv[thr].init(
					opt, nParties, setSize, psiSecParam, bitSize,
					chls[leaderIdx], otCountRecv, otRecv[thr], otSend[thr],
					osuCrypto::ZeroBlock, false);
				recv[thr].getOPRFkeys(leaderIdx, binsVec[r], chls[leaderIdx], false);
				recv[thr].recvSSTableBased(
					leaderIdx, binsVec[r], recvSSPayLoads[r][0], chls[leaderIdx], FourModulo, r);
			}
		}
		

#pragma endregion
		// syncHelper(myIdx, chls);
		auto Phase1Done = timer.setTimePoint("Phase1: secretsharingDone");

#pragma region prepare_UpdateValues
		// ###########################################
		// ### generate values and send to others by OLEs ####
		// ###########################################
		u64 UpdateValueSize = bins.mSimpleBins.mBins.size();						 // binNum
		std::vector<std::vector<std::vector<NTL::ZZ_p>>> genUpdateValues(4);		 // 4*UpdateValueSize*totalNumShares
		std::vector<std::vector<std::vector<osuCrypto::block>>> sendUpdateValues(4); // 4 * n * bins.size()
		std::vector<std::vector<std::vector<osuCrypto::block>>> recvUpdateValues(4);
		std::vector<std::vector<std::vector<NTL::ZZ>>> serverUpdateValues(4);
		std::vector<std::vector<osuCrypto::block>> endValues(1);

		for (u64 i = 0; i < recvUpdateValues.size(); i++)
		{
			recvUpdateValues[i].resize(totalNumShares);
			sendUpdateValues[i].resize(totalNumShares);
			for (u64 j = 0; j < recvUpdateValues[i].size(); j++)
			{
				recvUpdateValues[i][j].resize(UpdateValueSize);
				sendUpdateValues[i][j].resize(UpdateValueSize);
			}
		}

		for (u64 i = 0; i < serverUpdateValues.size(); i++)
		{
			serverUpdateValues[i].resize(nParties);
			for (u64 j = 0; j < serverUpdateValues[i].size(); j++)
			{
				serverUpdateValues[i][j].resize(UpdateValueSize);
			}
		}

		for (u64 i = 0; i < endValues.size(); i++)
		{
			endValues[i].resize(UpdateValueSize);
		}

		if (myIdx != leaderIdx)
		{
			for (u64 i = 0; i < 4; i++)
			{
				NTL::ZZ currentModulo = NTL::conv<NTL::ZZ>(FourModulo[i]);
				genUpdateValues[i].resize(UpdateValueSize);
				for (u64 j = 0; j < genUpdateValues[i].size(); j++)
				{
					genUpdateValues[i][j].resize(totalNumShares);
					genUpdateValues[i][j] = GenerateUpdateValues(totalNumShares, threshold, currentModulo);
					NTL::ZZ_p::init(p);
				}
				for (u64 j = 0; j < totalNumShares; j++)
					for (u64 k = 0; k < UpdateValueSize; k++)
						NTL::BytesFromZZ((u8 *)&sendUpdateValues[i][j][k], rep((genUpdateValues[i][k][j])), sizeof(osuCrypto::block));
			}
		}

		if (myIdx != leaderIdx)
		{
			for (u64 i = 0; i < 4; i++)
				for (u64 j = 0; j < UpdateValueSize; j++)
				{
					unsigned char buf[32 / 8];
					NTL::ZZ value = NTL::conv<NTL::ZZ>(genUpdateValues[i][j][totalNumShares - 1]);
					NTL::BytesFromZZ(buf, value, 32 / 8);
					chls[leaderIdx][0]->send(&buf, 32 / 8);
				}
		}
		else
		{
			// leader 并行从每个 client 接收
			for_each_party_parallel(nParties - 1, [&](u64 pIdx)
									{
                for(u64 i = 0; i < 4; i++){
                    for(u64 j = 0; j < UpdateValueSize; j++) {
                        unsigned char buf[32/8];
                        chls[pIdx][0]->recv(&buf, 32/8);
                        ZZFromBytes(serverUpdateValues[i][pIdx][j], buf, 32/8);
                    }
				} });
		}
#pragma endregion

#pragma region leader_update
		//*******************************************************
		//************leader updates its shares******************
		//*******************************************************
		if (myIdx == leaderIdx)
		{
			for (u64 i = 0; i < 4; i++)
			{
				NTL::ZZ mod = NTL::conv<NTL::ZZ>(FourModulo[i]);
				for (u64 j = 0; j < nParties - 1; j++)
					for (u64 k = 0; k < UpdateValueSize; k++)
					{
						serverUpdateValues[i][nParties - 1][k] += serverUpdateValues[i][j][k];
						serverUpdateValues[i][nParties - 1][k] %= mod;
					}
			}

			for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mCuckooBins.mBins[bIdx];
				if (!bin.isEmpty())
				{
					u64 inputIdx = bin.idx();
					for (u64 i = 0; i < 4; i++)
					{
						NTL::ZZ mod = NTL::conv<NTL::ZZ>(FourModulo[i]);
						NTL::ZZ num1 = ServerShares[i][inputIdx];
						NTL::ZZ num2 = serverUpdateValues[i][nParties - 1][bIdx];
						NTL::ZZ res = AddMod(num1, num2, mod);
						ServerShares[i][inputIdx] = res; // updates shares
					}
				}
			}
		}
#pragma endregion

#pragma region OLE
		//*******************************************************
		//**********************OLE Phase************************
		//*******************************************************
		// syncHelper(myIdx, chls);

		auto OLEstart = timer.setTimePoint("OLEstart");
		constexpr ui32 logn = 13;
		const ui32 oleSize = 1 << logn;
		const ui64 up = 4294475777ULL;
		typedef DCRT_Poly_Ring<params<ui64>, logn> PlaintextRing;
		typedef EncodingContext<PlaintextRing, up> encoding_context_t;
		typedef DCRT_Ring<fast_four_limb_reduction_params> IntCryptoRing;
		typedef DCRT_Fast_Four_Limb_Reduction_Params<IntCryptoRing, up> dcrt_params_t;
		typedef BFV_DCRT<encoding_context_t, dcrt_params_t> SchemeType;
		// leader invokes leaderOleNum OLEs with each client
		u64 leaderOleNum = (nParties - 1) * (bins.mCuckooBins.mBinCount[0] * bins.mCuckooBins.mParams.mSenderBinSize[0] + bins.mCuckooBins.mBinCount[1] * bins.mCuckooBins.mParams.mSenderBinSize[1]);
		// std::cout<<"leaderOleNum: "<< leaderOleNum<<std::endl;
		u64 leaderBoleNum = ceil(leaderOleNum / (oleSize * 1.0));	// bolenum = olenum / 8192 for each client
		std::vector<std::vector<ui128>> leaderInput(leaderBoleNum); // input for each client

		for (u64 i = 0; i < leaderInput.size(); i++)
		{
			leaderInput[i].resize(oleSize);
		}

		std::vector<std::vector<std::vector<ui128>>> randomValue(nParties - 1); // ri :n-1 * 64 * mbins
		std::vector<std::vector<std::vector<ui128>>> partUpValue(nParties - 1); // δi :n-1 * 64 * mbins
		std::vector<std::vector<std::vector<ui128>>> recvOLE(nParties - 1);

		std::vector<std::vector<ui128>> randomValueForLeader(leaderBoleNum); // a
		std::vector<std::vector<ui128>> partUpValueForLeader(leaderBoleNum); // b
		std::vector<std::vector<ui128>> UpdateForLeader(leaderBoleNum);

		std::vector<std::vector<ui128>> ReInput(leaderBoleNum);

		// prepare for OLE
		for (u64 i = 0; i < randomValueForLeader.size(); i++)
		{
			randomValueForLeader[i].resize(oleSize);
			partUpValueForLeader[i].resize(oleSize);
			UpdateForLeader[i].resize(oleSize);
		}

		// prepare random values
		if (myIdx != leaderIdx)
		{
			// each client generates random values for OLE phase size:n-1 * 64 * binsNum
			for (int i = 0; i < nParties - 1; i++)
			{

				randomValue[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
				partUpValue[i].resize(bins.mSimpleBins.mMaxBinSize[1]);

				for (int j = 0; j < bins.mSimpleBins.mMaxBinSize[1]; j++)
				{
					randomValue[i][j].resize(UpdateValueSize);
					partUpValue[i][j].resize(UpdateValueSize);

					for (int k = 0; k < UpdateValueSize; k++)
					{
						NTL::RandomBnd(element, p);
						// element = NTL::ZZ(1);
						NTL::ZZ zz_value = NTL::conv<NTL::ZZ>(element);
						// std::cout<<"randomValue[i][j][k]_ = "<<zz_value<<std::endl;
						randomValue[i][j][k] = ZZ_to_ui128(zz_value);
						// // randomValue[i][j][k] = 1;

						NTL::RandomBnd(element, p);
						// element = NTL::ZZ(0);
						zz_value = NTL::conv<NTL::ZZ>(element);
						// std::cout<<"partUpValue[i][j][k]_ = "<<zz_value<<std::endl;

						partUpValue[i][j][k] = ZZ_to_ui128(zz_value);
					}
				}
			}

			int row = 0, col = 0;
			int count = 0;

			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++)
				{
					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else // 64
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}
					for (u64 eIdx = 0; eIdx < numMax; eIdx++)
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						randomValueForLeader[row][col] = randomValue[pIdx][eIdx][bIdx];
						partUpValueForLeader[row][col] = partUpValue[pIdx][eIdx][bIdx];
						col++;
					}
				}
			}
		}

		for (int i = 0; i < recvOLE.size(); i++) // n-1 * leaderBoleNum * oleSize
		{
			recvOLE[i].resize(leaderBoleNum);
			for (int j = 0; j < recvOLE[i].size(); j++)
			{
				recvOLE[i][j].resize(oleSize);
			}
		}

		// leader (as OLE receiver) and others invoke OLEs
		auto OLEstart1 = timer.setTimePoint("");
		if (myIdx == leaderIdx)
		{
			int row = 0, col = 0;
			// prepare input[][]
			for (int uIdx = 0; uIdx < nParties - 1; uIdx++)
			{
				NTL::SetSeed(diffseed);
				for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
				{
					auto &bin = bins.mCuckooBins.mBins[bIdx];
					ui128 inputIdx;
					if (!bin.isEmpty())
					{
						inputIdx = block_to_u128(set[bin.idx()]);
						// std::cout<<"bin: "<<inputIdx<<std::endl;
					}
					else
					{
						NTL::RandomBnd(element, p);
						inputIdx = ZZ_to_ui128(element);
						// std::cout<<"input = "<<inputIdx<<std::endl;
						// inputIdx = 0;
					}

					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (int numinBin = 0; numinBin < numMax; numinBin++) // 32 or 64
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						leaderInput[row][col] = inputIdx;
						col++;
					}
				}
			}

			// —— 并行与每个 client 做 ReceiverOnline（线程局部 ReInputLocal）
			for_each_party_parallel(nParties - 1, [&](u64 pIdx)
									{
                const SchemeType scheme(std_dev);
                auto chl = chls[pIdx][0];
                using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
                using SecretKey     = typename SchemeType::SecretKey;
                KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
                sendPublicKey(kpSeeded.pkSeeded, *chl);
                SecretKey& sk = kpSeeded.sk;

                using encoding_context_t = typename SchemeType::encoding_context_t;
                using encoding_input_t   = typename encoding_context_t::encoding_input_t;

                // 线程局部 ReInputLocal，避免多个线程共享写
                std::vector<std::vector<ui128>> ReInputLocal(leaderBoleNum);
                for (ui32 i = 0; i < leaderBoleNum; i++) {
                    ReInputLocal[i].resize(oleSize);
                    for (ui32 j = 0; j < oleSize; j++) {
                        ui128 input = 0, element128 = leaderInput[i][j];
                        for (ui32 k = 0; k < 4; k++)
                            input |= static_cast<ui128>(element128) << ((3-k)*32);
                        ReInputLocal[i][j] = input;
                    }
                }

                FourBOLEReceiverInputs<encoding_input_t> FourInputs(leaderBoleNum);
                FourInputs.processModule(ReInputLocal);

                std::vector<BOLEReceiverOutput<encoding_input_t>> FourOutputs(
                    4, BOLEReceiverOutput<encoding_input_t>(FourInputs.receiverInputs[0].numBlocks));

                FourOutputs[0] = ReceiverOnline<4293230593ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[0], sk, scheme, *chl);
                FourOutputs[1] = ReceiverOnline<4293836801ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[1], sk, scheme, *chl);
                FourOutputs[2] = ReceiverOnline<4293918721ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[2], sk, scheme, *chl);
                FourOutputs[3] = ReceiverOnline<4294475777ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[3], sk, scheme, *chl);

                for (int BoleIdx = 0; BoleIdx < (int)leaderBoleNum; BoleIdx++)
                    for (u64 i = 0; i < oleSize; i++) {
                        ui128 res = 0;
                        for (u64 j = 0; j < 4; j++)
                            res |= static_cast<ui128>(FourOutputs[j].cBlocks[BoleIdx][i]) << ((3-j)*32);
                        recvOLE[pIdx][BoleIdx][i] = res;
                    } });
		}
		else
		{
			// clients (as OLE Sender) and leader invoke OLEs
			const SchemeType scheme(std_dev);
			auto chl = chls[leaderIdx][0];

			using SeededPublicKey = typename SchemeType::PublicKeySeeded;
			using PublicKey = typename SchemeType::PublicKey;
			SeededPublicKey seededPK;
			receivePublicKey(seededPK, *chl);
			PublicKey pk = seededPK.expand();

			int row = 0, col = 0;

			// prepare update values
			for (int uIdx = 0; uIdx < nParties - 1; uIdx++)
			{
				for (u64 bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
				{
					ui128 res = 0;
					for (u64 i = 0; i < 4; i++)
					{
						NTL::ZZ part_zz = NTL::ZZFromBytes((u8 *)&sendUpdateValues[i][uIdx][bIdx], sizeof(osuCrypto::block));
						ui128 part = ZZ_to_ui128(part_zz);
						res |= static_cast<ui128>(part) << ((3 - i) * 32);
					}

					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else // 64
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (int numinBin = 0; numinBin < numMax; numinBin++)
					{

						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						UpdateForLeader[row][col] = res;
						col++;
					}
				}
			}

			// invoke OLEs with leader
			using encoding_context_t = typename SchemeType::encoding_context_t;
			using encoding_input_t = typename encoding_context_t::encoding_input_t;

			std::vector<std::vector<encoding_input_t>> aVecs(4);
			std::vector<std::vector<encoding_input_t>> bVecs(4);

			for (ui32 i = 0; i < 4; i++)
			{
				aVecs[i].resize(leaderBoleNum);
				bVecs[i].resize(leaderBoleNum);
				for (ui32 BoleIdx = 0; BoleIdx < leaderBoleNum; BoleIdx++)
				{
					for (ui32 j = 0; j < oleSize; j++)
					{
						u64 shift = (3 - i) * 32;
						aVecs[i][BoleIdx].vals[j] = ((randomValueForLeader[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
						ui128 randnum_a = ((partUpValueForLeader[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];
						ui128 randnum_b = ((UpdateForLeader[BoleIdx][j] >> (shift)) & 0xFFFFFFFF) % FourModulo[i];

						bVecs[i][BoleIdx].vals[j] = (randnum_b + FourModulo[i] - randnum_a) % FourModulo[i]; // 需要mod FourModulo[i] 吗？？？？？
					}
				}
			}
			std::vector<BOLESenderInput<encoding_input_t>> FourSenderInput;
			for (ui32 i = 0; i < 4; i++)
			{
				FourSenderInput.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[i], bVecs[i]));
			}
			SenderOnline<4293230593ULL, 13, 4, SchemeType>(FourSenderInput[0], pk, scheme, *chl);
			SenderOnline<4293836801ULL, 13, 4, SchemeType>(FourSenderInput[1], pk, scheme, *chl);
			SenderOnline<4293918721ULL, 13, 4, SchemeType>(FourSenderInput[2], pk, scheme, *chl);
			SenderOnline<4294475777ULL, 13, 4, SchemeType>(FourSenderInput[3], pk, scheme, *chl);
		}
		auto OLEend1 = timer.setTimePoint("");
		// std::cout << "Party [" << myIdx << "] finish OLE1 in " << std::chrono::duration_cast<std::chrono::milliseconds>(OLEend1 - OLEstart1).count() << " ms" << std::endl;

		// —— client↔client OLE
		// client and other clients invoke OLEs

		// the number of OLEs between two clients
		u64 ClientOleNum = bins.mSimpleBins.mBinCount[0] * bins.mSimpleBins.mMaxBinSize[0]
						+ bins.mSimpleBins.mBinCount[1] * bins.mSimpleBins.mMaxBinSize[1];
		u64 ClientBoleNum = ceil(ClientOleNum / (1.0 * oleSize));
		// std::cout<<"ClientBoleNum: "<< ClientBoleNum<<std::endl;

		std::vector<std::vector<ui128>> ClientInput_origin(ClientBoleNum);
		std::vector<std::vector<ui128>> ClientInput(ClientBoleNum);

		// std::vector<std::vector<ui128>> randomValueForClient(ClientBoleNum);
		// std::vector<std::vector<ui128>> partUpValueForClient(ClientBoleNum);
		std::vector<std::vector<ui128>> UpdateForClient(ClientBoleNum);

		for (int i = 0; i < (int)ClientInput_origin.size(); i++)
		{
			ClientInput_origin[i].resize(oleSize);
			ClientInput[i].resize(oleSize);
		}

		for (u64 i = 0; i < UpdateForClient.size(); i++)
		{
			// randomValueForClient[i].resize(oleSize);
			// partUpValueForClient[i].resize(oleSize);
			UpdateForClient[i].resize(oleSize);
		}

		if (myIdx != leaderIdx)
		{
			u64 row = 0, col = 0;
			NTL::SetSeed(diffseed);

			// prepare client_input[][]
			for (u64 bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mSimpleBins.mBins[bIdx];
				auto eNum = bin.mIdx.size();
				if (eNum > 0)
				{
					for (u64 i = 0; i < eNum; i++)
					{
						if (col >= oleSize) { row++; col = 0; }
						ClientInput_origin[row][col] = block_to_u128(set[bin.mIdx[i]]);
						col++;
					}
				}
				u64 numMax;
				if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					numMax = bins.mSimpleBins.mMaxBinSize[0];
				else // 64
					numMax = bins.mSimpleBins.mMaxBinSize[1];

				for (u64 i = eNum; i < numMax; i++) // dummy element for OLEs
				{
					if (col >= oleSize) { row++; col = 0; }
					NTL::RandomBnd(element, p);
					ClientInput_origin[row][col] = ZZ_to_ui128(element);
					col++;
				}
			}

			for (u64 i = 0; i < ClientInput_origin.size(); i++)
			{
				for (u64 j = 0; j < ClientInput_origin[i].size(); j++)
				{
					ui128 input = 0;
					ui128 element = ClientInput_origin[i][j];
					for (ui32 k = 0; k < 4; k++)
					{
						input |= static_cast<ui128>(element) << ((3 - k) * 32);
					}
					ClientInput[i][j] = input;
				}
			}

			// 	// prepare a(random values) and b(partial values for updating)

			recvOLE.resize(nParties - 1);
			for (int i = 0; i < (int)recvOLE.size(); i++)
			{
				recvOLE[i].resize(ClientBoleNum);
				for (int j = 0; j < (int)recvOLE[i].size(); j++)
				{
					recvOLE[i][j].resize(oleSize);
				}
			}

			// =========================
			// [MT] 并行化：每个 pIdx 一个线程
			// 把原来的两段 for(pIdx) 合并为一个，并将“接收/发送”顺序化放在同一线程内
			// =========================
			std::vector<std::thread> workers;                // [MT]
			workers.reserve(nParties - 1);                   // [MT]

			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)  // [MT] 统一一段循环
			{
				workers.emplace_back([&, pIdx]() {           // [MT] 开线程
					using encoding_context_t = typename SchemeType::encoding_context_t;
					using encoding_input_t   = typename encoding_context_t::encoding_input_t;

					// 小工具：把四路 32-bit 结果拼回 ui128
					auto pack_outputs = [&](const std::vector<BOLEReceiverOutput<encoding_input_t>>& FourOutputs,
											int BoleIdx, u64 iSlot) -> ui128 {
						ui128 res = 0;
						for (u64 j = 0; j < 4; j++)
							res |= static_cast<ui128>(FourOutputs[j].cBlocks[BoleIdx][iSlot]) << ((3 - j) * 32);
						return res;
					};

					// 接收方流程
					auto do_receiver = [&](u64 peer) {
						auto chl = chls[peer][0];
						const SchemeType scheme(std_dev);
						using KeyPairSeeded = typename SchemeType::KeyPairSeeded;
						using SecretKey     = typename SchemeType::SecretKey;

						KeyPairSeeded kpSeeded = scheme.KeyGenSeeded();
						sendPublicKey(kpSeeded.pkSeeded, *chl);
						SecretKey &sk = kpSeeded.sk;

						FourBOLEReceiverInputs<encoding_input_t> FourInputs(ClientBoleNum);
						FourInputs.processModule(ClientInput);

						std::vector<BOLEReceiverOutput<encoding_input_t>> FourOutputs(
							4, BOLEReceiverOutput<encoding_input_t>(FourInputs.receiverInputs[0].numBlocks));

						FourOutputs[0] = ReceiverOnline<4293230593ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[0], sk, scheme, *chl);
						FourOutputs[1] = ReceiverOnline<4293836801ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[1], sk, scheme, *chl);
						FourOutputs[2] = ReceiverOnline<4293918721ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[2], sk, scheme, *chl);
						FourOutputs[3] = ReceiverOnline<4294475777ULL, 13, 4, SchemeType>(FourInputs.receiverInputs[3], sk, scheme, *chl);

						for (int BoleIdx = 0; BoleIdx < (int)ClientBoleNum; BoleIdx++)
							for (u64 i = 0; i < oleSize; i++)
								recvOLE[peer][BoleIdx][i] = pack_outputs(FourOutputs, BoleIdx, i);
					};

					// 发送方流程（使用线程局部的批缓存，避免共享写）
					auto do_sender = [&](u64 peer) {
						auto chl = chls[peer][0];

						// 先把 randomValue/partUpValue 平铺到线程局部的 *_local
						std::vector<std::vector<ui128>> randomValueForClient_local(ClientBoleNum, std::vector<ui128>(oleSize));
						std::vector<std::vector<ui128>> partUpValueForClient_local (ClientBoleNum, std::vector<ui128>(oleSize));

						int row2 = 0, col2 = 0;
						for (u64 bIdx = 0; bIdx < UpdateValueSize; bIdx++)
						{
							u64 numMax = (bIdx < bins.mSimpleBins.mBinCount[0])
									?  bins.mSimpleBins.mMaxBinSize[0]
									:  bins.mSimpleBins.mMaxBinSize[1];

							for (u64 eIdx = 0; eIdx < numMax; eIdx++)
							{
								if (col2 >= oleSize) { row2++; col2 = 0; }
								randomValueForClient_local[row2][col2] = randomValue[peer][eIdx][bIdx];
								partUpValueForClient_local [row2][col2] = partUpValue [peer][eIdx][bIdx];
								col2++;
							}
						}

						// OLE 发送
						const SchemeType scheme(std_dev);
						using SeededPublicKey = typename SchemeType::PublicKeySeeded;
						using PublicKey = typename SchemeType::PublicKey;
						SeededPublicKey seededPK;
						receivePublicKey(seededPK, *chl);
						PublicKey pk = seededPK.expand();

						std::vector<std::vector<encoding_input_t>> aVecs(4), bVecs(4);
						for (ui32 i = 0; i < 4; i++)
						{
							aVecs[i].resize(ClientBoleNum);
							bVecs[i].resize(ClientBoleNum);
							for (ui32 BoleIdx = 0; BoleIdx < ClientBoleNum; BoleIdx++)
							{
								for (ui32 j = 0; j < oleSize; j++)
								{
									u64 shift = (3 - i) * 32;
									ui128 r  = ((randomValueForClient_local[BoleIdx][j] >> shift) & 0xFFFFFFFF) % FourModulo[i];
									r = (FourModulo[i] - r) % FourModulo[i];                    // a = -rand (mod p_i)
									aVecs[i][BoleIdx].vals[j] = r;

									ui128 bv = ((partUpValueForClient_local [BoleIdx][j] >> shift) & 0xFFFFFFFF) % FourModulo[i];
									bVecs[i][BoleIdx].vals[j] = bv;
								}
							}
						}

						std::vector<BOLESenderInput<encoding_input_t>> FourSenderInput;
						for (ui32 i = 0; i < 4; i++)
							FourSenderInput.emplace_back(BOLESenderInput<encoding_input_t>(aVecs[i], bVecs[i]));

						SenderOnline<4293230593ULL, 13, 4, SchemeType>(FourSenderInput[0], pk, scheme, *chl);
						SenderOnline<4293836801ULL, 13, 4, SchemeType>(FourSenderInput[1], pk, scheme, *chl);
						SenderOnline<4293918721ULL, 13, 4, SchemeType>(FourSenderInput[2], pk, scheme, *chl);
						SenderOnline<4294475777ULL, 13, 4, SchemeType>(FourSenderInput[3], pk, scheme, *chl);
					};

					// 同一对端的双向交互在同一线程内顺序执行，避免通道并发
					if (myIdx > pIdx) {
						do_receiver(pIdx);
						do_sender(pIdx);
					} else if (myIdx < pIdx) {
						do_sender(pIdx);
						do_receiver(pIdx);
					} else {
						// myIdx == pIdx 不会发生
					}
				});
			}

			for (auto &t : workers) t.join();                // [MT] 等待所有对端线程结束
		}


		auto OLEend = timer.setTimePoint("OLEend");
		auto OLEtime = std::chrono::duration_cast<std::chrono::milliseconds>(OLEend - OLEstart).count();
		// std::cout << "p" << myIdx << " OLEtime: " << OLEtime / 1000.0 << std::endl;
#pragma endregion

#pragma region Processing OLE results（保持原逻辑）
		std::vector<std::vector<std::vector<ui128>>> OLE_result(nParties - 1);
		for (int i = 0; i < OLE_result.size(); i++)
		{
			OLE_result[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
			for (int j = 0; j < OLE_result[i].size(); j++)
			{
				OLE_result[i][j].resize(bins.mSimpleBins.mBins.size());
			}
		}

		if (myIdx == leaderIdx)
		{

			// Dimension conversion: n-1 * leaderBolenum * olesize --> n-1 * (n-1 * 32/64 * binNum)
			for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				std::vector<std::vector<std::vector<ui128>>> temp(nParties - 1); // n-1*64*binNum

				for (int i = 0; i < temp.size(); i++)
				{
					temp[i].resize(bins.mSimpleBins.mMaxBinSize[1]);
					for (int j = 0; j < temp[i].size(); j++)
					{
						temp[i][j].resize(bins.mSimpleBins.mBins.size());
					}
				}

				int row = 0, col = 0;
				for (int i = 0; i < nParties - 1; i++)
				{
					for (int bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
					{
						u64 numMax;
						if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
						{
							numMax = bins.mSimpleBins.mMaxBinSize[0];
						}
						else // 64
						{
							numMax = bins.mSimpleBins.mMaxBinSize[1];
						}

						for (int j = 0; j < numMax; j++)
						{
							if (col >= oleSize)
							{
								row++;
								col = 0;
							}
							temp[i][j][bIdx] = recvOLE[pIdx][row][col];
							col++;
						}
					}
				}

				for (int i = 0; i < temp.size(); i++)
				{
					for (int j = 0; j < temp[i].size(); j++)
					{
						for (int k = 0; k < temp[i][j].size(); k++)
						{
							// OLE_result[i][j][k] = (ui128)(OLE_result[i][j][k] + temp[i][j][k]) % up;
							std::vector<ui128> part(4);
							std::vector<ui128> addNum(4);
							ui128 res = 0;
							for (int idx = 0; idx < 4; idx++)
							{
								ui128 tempNum;
								u64 shift = (3 - idx) * 32;
								part[idx] = ((OLE_result[i][j][k] >> (shift)) & 0xFFFFFFFF);
								addNum[idx] = ((temp[i][j][k] >> (shift)) & 0xFFFFFFFF);
								tempNum = (part[idx] + addNum[idx]) % FourModulo[idx];
								res |= static_cast<ui128>(tempNum) << (shift);
							}
							OLE_result[i][j][k] = res;
						}
					}
				}
			}
		}
		else
		{

			for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				int row = 0, col = 0;

				for (int bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
				{
					u64 numMax;
					if (bIdx < bins.mSimpleBins.mBinCount[0]) // 32
					{
						numMax = bins.mSimpleBins.mMaxBinSize[0];
					}
					else // 64
					{
						numMax = bins.mSimpleBins.mMaxBinSize[1];
					}

					for (int j = 0; j < numMax; j++)
					{
						if (col >= oleSize)
						{
							row++;
							col = 0;
						}
						OLE_result[pIdx][j][bIdx] = recvOLE[pIdx][row][col];
						col++;
					}
				}
			}

			for (int bIdx = 0; bIdx < bins.mSimpleBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mSimpleBins.mBins[bIdx];
				auto eNum = bin.mIdx.size();

				if (eNum > 0)
				{
					for (u64 i = 0; i < eNum; i++)
					{
						ui128 inputIdx = block_to_u128(set[bin.mIdx[i]]);
						ui128 random = randomValue[myIdx][i][bIdx];
						ui128 partialvalue = partUpValue[myIdx][i][bIdx];

						ui128 res = 0;
						for (u64 idx = 0; idx < 4; idx++)
						{
							u64 shift = (3 - idx) * 32;
							ui128 random_part = ((random >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 partialvalue_part = ((partialvalue >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 temp = (((ui128)FourModulo[idx] - random_part) * inputIdx + partialvalue_part) % FourModulo[idx];
							res |= static_cast<ui128>(temp) << (shift);
						}
						OLE_result[myIdx][i][bIdx] = res;
					}
				}
			}

			for (int i = 1; i < nParties - 1; i++)
			{
				for (int j = 0; j < bins.mSimpleBins.mMaxBinSize[1]; j++)
				{
					for (int k = 0; k < bins.mSimpleBins.mBins.size(); k++)
					{
						// OLE_result[0][j][k] = (ui128)(OLE_result[0][j][k] + OLE_result[i][j][k]) % up;
						ui128 res = 0;
						for (int idx = 0; idx < 4; idx++)
						{
							u64 shift = (3 - idx) * 32;
							ui128 num1 = ((OLE_result[0][j][k] >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 num2 = ((OLE_result[i][j][k] >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 temp = (num1 + num2) % FourModulo[idx];
							res |= static_cast<ui128>(temp) << (shift);
						}
						OLE_result[0][j][k] = res;
					}
				}
			}
		}

#pragma endregion
		// syncHelper(myIdx, chls);

		auto phase2Done = timer.setTimePoint("Phase2: updatesharesDone");
		// std::cout << "Party [" << myIdx << "] finish Phase 2." << std::endl;

#pragma region OPPRF Phase3

		std::vector<std::vector<osuCrypto::block>> endPayLoads(nParties - 1); // server obtains updated shares from clients
		std::vector<std::vector<std::vector<osuCrypto::block>>> endPayLoads_divide(4);

		for (u64 i = 0; i < endPayLoads.size(); i++)
		{
			endPayLoads[i].resize(setSize);
		}

		for (u64 i = 0; i < endPayLoads_divide.size(); i++)
		{
			endPayLoads_divide[i].resize(nParties - 1);
			for (u64 j = 0; j < endPayLoads_divide[i].size(); j++)
			{
				endPayLoads_divide[i][j].resize(setSize);
			}
		}

		if (myIdx == leaderIdx)
		{
			// leader 端：对每个对端并行（recv）
			std::vector<std::thread> workers;
			workers.reserve(nParties - 1);

			for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
			{
				workers.emplace_back([&, pIdx]()
									 {
						for (u64 r = 0; r < 4; ++r)
						{
						const u64 thr = pIdx + r * nParties; // 每轮的正确索引

						recv[thr].init(
							opt, nParties, setSize, psiSecParam, bitSize,
							chls[pIdx], otCountRecv, otRecv[thr], otSend[thr],
							osuCrypto::ZeroBlock, false
						);
						recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false);
						recv[thr].recvSSTableBased(
							pIdx, bins, endPayLoads_divide[r][pIdx],
							chls[pIdx], FourModulo, r
						);
				 } });
			}
			for (auto &t : workers)
				t.join();
		}
		else
		{
			// client 端：与 leader 单链路（send）
			for (u64 r = 0; r < 4; ++r)
			{
				const u64 thr = r;

				send[thr].init(
					opt, nParties, setSize, psiSecParam, bitSize,
					chls[leaderIdx], otCountSend, otSend[thr], otRecv[thr],
					prng.get<osuCrypto::block>(), false);
				send[thr].getOPRFkeys(leaderIdx, binsVec[r], chls[leaderIdx], false);
				send[thr].sendSSTableBased(
					leaderIdx, binsVec[r], recvSSPayLoads[r][0], OLE_result[0],
					chls[leaderIdx], FourModulo, r);
			}
		}

		if (myIdx == leaderIdx)
		{
			for (u64 i = 0; i < endPayLoads.size(); ++i)
			{
				for (u64 j = 0; j < endPayLoads[i].size(); ++j)
				{
					u128 res = 0;
					for (u64 idx = 0; idx < 4; ++idx)
					{
						u128 conver_value = block_to_u128(endPayLoads_divide[idx][i][j]);
						u128 temp = (conver_value & 0xFFFFFFFF);
						res |= static_cast<u128>(temp) << ((3 - idx) * 32);
					}
					endPayLoads[i][j] = u128_to_block(res);
				}
			}
		}

		//  auto test1 = timer.setTimePoint("test");
#pragma endregion

#pragma region send_OLE_index

		std::vector<std::vector<osuCrypto::block>> OleIndex(nParties - 1);
		for (u64 i = 0; i < OleIndex.size(); i++)
			OleIndex[i].resize(setSize);

		if (myIdx == leaderIdx)
		{
			for_each_party_parallel(nParties - 1, [&](u64 pIdx)
									{
                u64 thr = pIdx + 4 * nParties;
                recv[thr].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[thr], otSend[thr], osuCrypto::ZeroBlock, false); });
		}
		else
		{
			send[4].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[4], otRecv[4], prng.get<osuCrypto::block>(), false);
		}

		if (myIdx == leaderIdx)
		{
			for_each_party_parallel(nParties - 1, [&](u64 pIdx)
									{
                u64 thr = pIdx + 4 * nParties;
                recv[thr].getOPRFkeys(pIdx, bins, chls[pIdx], false); });
		}
		else
		{
			send[4].getOPRFkeys(leaderIdx, binsVec[4], chls[leaderIdx], false);
		}

		if (myIdx == leaderIdx)
		{
			for_each_party_parallel(nParties - 1, [&](u64 pIdx)
									{
                u64 thr = pIdx + 4 * nParties;
                recv[thr].recvSSTableBased(pIdx, bins, OleIndex[pIdx], chls[pIdx]); });
		}
		else
		{
			send[4].sendSSTableBased(leaderIdx, binsVec[4], chls[leaderIdx]);
		}
// 		auto test2 = timer.setTimePoint("test");
#pragma endregion

#pragma region leader process data（保持原逻辑）

		std::vector<std::vector<ui128>> endShares(totalNumShares); // contains updated shares of each party n * setsize
		std::vector<std::vector<ui128>> leader_recv_value(4);

		if (myIdx == leaderIdx)
		{

			for (int i = 0; i < endShares.size(); i++)
			{
				endShares[i].resize(setSize);
			}

			// process clients' shares
			for (int bIdx = 0; bIdx < bins.mCuckooBins.mBins.size(); bIdx++)
			{
				auto &bin = bins.mCuckooBins.mBins[bIdx];
				if (!bin.isEmpty())
				{
					u64 inputIdx = bin.idx();
					for (int pIdx = 0; pIdx < nParties - 1; pIdx++)
					{
						osuCrypto::block recv_value = endPayLoads[pIdx][inputIdx];
						ui128 recv_value_128 = block_to_u128(recv_value); // client pidx updated share

						ui128 index = block_to_u128(OleIndex[pIdx][inputIdx]);
						index = index & 0x3F; //

						ui128 value1 = OLE_result[pIdx][index][bIdx];
						ui128 value2 = recv_value_128;

						ui128 res = 0;
						for (int idx = 0; idx < 4; idx++)
						{
							u64 shift = (3 - idx) * 32;
							ui128 num1 = ((value1 >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 num2 = ((value2 >> (shift)) & 0xFFFFFFFF) % FourModulo[idx];
							ui128 temp = (num1 + num2) % FourModulo[idx];
							res |= static_cast<ui128>(temp) << (shift);

							// boost::multiprecision::uint256_t pp= res;
							// std::cout<<pp<<std::endl;
						}
						endShares[pIdx][inputIdx] = res; // clients' updated shares
					}
				}
			}

			// leader's shares

			for (u64 i = 0; i < setSize; i++)
			{
				ui128 res = 0;
				for (u64 idx = 0; idx < 4; idx++)
				{
					u64 shift = (3 - idx) * 32;
					ui128 value = ZZ_to_ui128(ServerShares[idx][i]);
					res |= static_cast<ui128>(value) << (shift);
				}
				endShares[nParties - 1][i] = res;
			}
		}

#pragma endregion
		// syncHelper(myIdx, chls);
		auto phase3Done = timer.setTimePoint("Phase3: collectsharesDone");
		// std::cout << "Party [" << myIdx << "] finish Phase 3." << std::endl;

#pragma region Intersection

		// 使用多线程重构秘密
		std::vector<std::vector<std::pair<int, ui128>>> endShares_T(setSize);
		std::unordered_set<u64> result;

		if (myIdx == leaderIdx)
		{
			// 1) 转置 endShares => endShares_T[eIdx][shareIdx] = (x=j+1, y=share)
			for (u64 i = 0; i < endShares_T.size(); i++)
			{
				endShares_T[i].resize(totalNumShares);
				for (u64 j = 0; j < totalNumShares; j++)
				{
					endShares_T[i][j].first = static_cast<int>(j + 1);
					endShares_T[i][j].second = endShares[j][i];
				}
			}

			// 2) 生成所有包含 leader 的阈值组合
			std::vector<std::vector<int>> all_combinations;
			get_combinations_iterative(static_cast<int>(totalNumShares) - 1,
									   static_cast<int>(threshold) - 1,
									   all_combinations);
			for (int i = 0; i < (int)all_combinations.size(); i++)
				all_combinations[i].push_back(static_cast<int>(leaderIdx));
		

			// 3) 多线程并行判定
			// int threads = std::thread::hardware_concurrency(); // 用 CPU 核心数
			// int threads = 10;
			int threads = nParties -1;
			std::vector<u8> hit(setSize, 0); // 标记每个元素是否在交集中
			std::vector<std::thread> workers;
			workers.reserve(threads);

			// 均匀划分 [0, setSize) 区间
			auto ceil_div = [](u64 a, u64 b)
			{ return (a + b - 1) / b; };
			const u64 chunk = ceil_div(setSize, (u64)threads);

			for (int t = 0; t < threads; ++t)
			{
				const u64 begin = (u64)t * chunk;
				const u64 end = std::min<u64>(setSize, begin + chunk);
				if (begin >= end)
					break;

				workers.emplace_back([&, begin, end]()
									 {
					for (u64 eIdx = begin; eIdx < end; ++eIdx) {
						// 遍历所有包含 leader 的阈值组合，只要有一组能重构出 set_zz[eIdx] 就命中
						for (const auto& comb : all_combinations) {
							int ok = reconstruct_secret(comb, endShares_T[eIdx], FourModuloZZ, set_zz[eIdx]);
							if (ok == 1) { hit[eIdx] = 1; break; }
						}
					} });
			}
			for (auto &th : workers)
				th.join();

			// 汇总结果
			for (u64 eIdx = 0; eIdx < setSize; ++eIdx)
				if (hit[eIdx])
					result.insert(eIdx);

		}

		auto getIntersection = timer.setTimePoint("getIntersection");
		
		// std::cout << "phase4 done. " << std::endl;

		if (myIdx == leaderIdx)
		{
			std::unordered_map<std::string, std::unordered_set<std::string>> element_to_parties;
			const char *dir_path = "./input";
			DIR *dir = opendir(dir_path);
			if (dir == NULL)
			{
				perror("opendir error");
				exit(-1);
			}
			struct dirent *entry;
			std::string leader = "P" + std::to_string(leaderIdx) + "_" + std::to_string(idxTrial) + ".txt";
			std::vector<std::string> element_files(nParties);
			for (int i = 0; i < element_files.size(); i++)
			{
				element_files[i] = "P" + std::to_string(i) + "_" + std::to_string(idxTrial) + ".txt";
			}
			while ((entry = readdir(dir)) != NULL)
			{
				std::string filename = entry->d_name;

				if (std::find(element_files.begin(), element_files.end(), std::string(filename)) != element_files.end())
				{

					std::string file_path = std::string(dir_path) + "/" + filename;

					std::ifstream file(file_path);

					if (!file.is_open())
					{
						std::cerr << "Failed to open file: " << file_path << std::endl;
						continue;
					}

					std::string element;
					while (getline(file, element))
					{
						element_to_parties[element].insert(filename);
					}

					// std::remove(file_path.c_str());
				}
			}

			closedir(dir);

			int count = 0;

			for (const auto &pair : element_to_parties)
			{
				if (pair.second.size() >= threshold && pair.second.count(leader) > 0)
				{
					count++;
				}
			}
			expected_intersection = count;
			// std::cout << "the number of intersection is " << result.size() << std::endl;
			// std::cout << "the number of expected_intersection is " << expected_intersection << std::endl;
		}

#pragma endregion

		if (myIdx == 0 || myIdx == leaderIdx)
		{
			auto phase1 = std::chrono::duration_cast<std::chrono::milliseconds>(Phase1Done - hashingDone).count();	   // secret sharing + opprf
			auto phase2 = std::chrono::duration_cast<std::chrono::milliseconds>(phase2Done - Phase1Done).count();	   // update share(OLE)
			auto phase3 = std::chrono::duration_cast<std::chrono::milliseconds>(phase3Done - phase2Done).count();	   // OPPRF
			auto phase4 = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - phase3Done).count(); // reconstruction

			// auto test1_time = std::chrono::duration_cast<std::chrono::milliseconds>(test1 - phase2Done).count();
			// auto test2_time = std::chrono::duration_cast<std::chrono::milliseconds>(test2 - test1).count();

			// auto leader_Ole = std::chrono::duration_cast<std::chrono::milliseconds>(OLEend1 - OLEstart1).count();

			double time = phase1 + phase2 + phase3 + phase4;
			double share_time = phase1 + phase2 + phase3;
			double recon_time = phase4;

			time /= 1000;
			share_time /= 1000;
			recon_time /= 1000;

			eachTime[idxTrial] = time; // s
			eachShareTime[idxTrial] = share_time;
			eachReconTime[idxTrial] = recon_time;

			dataSent = 0;
			dataRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;
			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx)
				{
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dataRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataRecv * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx)
				{
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}

			if (myIdx == leaderIdx)
			{
				// osuCrypto::Log::out << "#Output Intersection: " << result.size() << osuCrypto::Log::endl;
				// osuCrypto::Log::out << "#Expected Intersection: " << expected_intersection << osuCrypto::Log::endl;
				num_intersection = result.size();
				std::string filename = "time_leader_MT.txt";
				std::ofstream oFile;
				oFile.open(filename, std::ios::out | std::ios::app);
				oFile << "numParty: " << nParties << " "
					  << "threshold: " << threshold << " "
					  << "setSize: " << setSize << "\n"
					  << "Expected Intersection: " << expected_intersection << "\n"
					  << "Output Intersection: " << result.size() << "\n"
					  << "Phase1 time: " << phase1 << " ms\n"
					  << "Phase2 time: " << phase2 << " ms\n"
					  // <<"OPPRF1 time: " << test1_time<< " ms\n"
					  // <<"OPPRF2 time: " << test2_time<< " ms\n"
					  // <<"leaderOLE time: " << leader_Ole<< " ms\n"
					  << "Phase3 time: " << phase3 << " ms\n"
					  << "Phase4 time: " << phase4 << " ms\n"
					  << "share time: " << share_time << " s\n"
					  << "recon time: " << recon_time << " s\n"
					  << "Total time: " << time << " s\n"
					  << "------------------\n";
			}

			// std::cout
			// 	<< "Total time: " << time << " s\n"

			// 	<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			// 	<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			// 	<< "------------------\n";
			// std::cout << "setSize: " << setSize << "\n"
			// 		  << "Phase1 time: " << phase1 << " ms\n"
			// 		  << "Phase2 time: " << phase2 << " ms\n"
			// 		  << "Phase3 time: " << phase3 << " ms\n"
			// 		  << "Phase4 time: " << phase4 << " ms\n"
			// 		  << "share time: " << share_time << " ms\n"
			// 		  << "recon time: " << recon_time << " ms\n"
			// 		  << "Total time: " << time << " s\n"

			// 		  << "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			// 		  << "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			// 		  << "------------------\n";

			totalTime += time;
			totalShareTime += share_time;
			totalReconTime += recon_time;
			totalPhase1Time += phase1;
			totalPhase2Time += phase2;
			totalPhase3Time += phase3;
			totalPhase4Time += phase4;
		}

		deep_clear(shares_zz);
		deep_clear(ServerShares);
		deep_clear(genUpdateValues);
		deep_clear(sendUpdateValues);
		deep_clear(recvUpdateValues);
		deep_clear(serverUpdateValues);
		deep_clear(endValues);
		deep_clear(leaderInput);
		deep_clear(randomValue);
		deep_clear(partUpValue);
		deep_clear(recvOLE);
		deep_clear(randomValueForLeader);
		deep_clear(partUpValueForLeader);
		deep_clear(UpdateForLeader);
		deep_clear(ReInput);
		deep_clear(ClientInput_origin);
		deep_clear(ClientInput);
		// deep_clear(randomValueForClient);
		// deep_clear(partUpValueForClient);
		// deep_clear(UpdateForClient);
		deep_clear(OLE_result);
		deep_clear(endPayLoads);
		deep_clear(OleIndex);
		deep_clear(endShares);
		deep_clear(leader_recv_value);
		deep_clear(endShares_T);

		release_vector(FourModulo);
		release_vector(FourModuloZZ);
		release_vector(set_zz);
		release_vector(set);
		release_vector(otRecv);
		release_vector(otSend);
		release_vector(send);
		release_vector(recv);

		std::unordered_set<u64>().swap(result);
	}
	std::cout << osuCrypto::IoStream::lock;
	if (myIdx == 0 || myIdx == leaderIdx)
	{
		totalAvgTime = totalTime / nTrials;
		totalAvgShareTime = totalShareTime / nTrials;
		totalAvgReconTime = totalReconTime / nTrials;
		totalAvgPhase1Time = totalPhase1Time / nTrials;
		totalAvgPhase2Time = totalPhase2Time / nTrials;
		totalAvgPhase3Time = totalPhase3Time / nTrials;
		totalAvgPhase4Time = totalPhase4Time / nTrials;

		for (u64 i = 0; i < nTrials; i++)
		{
			total_sd += pow(eachTime[i] - totalAvgTime, 2);
			total_share_sd += pow(eachShareTime[i] - totalAvgShareTime, 2);
			total_recon_sd += pow(eachReconTime[i] - totalAvgReconTime, 2);
		}

		total_sd = sqrt(total_sd / nTrials);
		total_share_sd = sqrt(total_share_sd / nTrials);
		total_recon_sd = sqrt(total_recon_sd / nTrials);

		std::cout << "=========avg==========\n";
		runtime << "=========avg==========\n";
		runtime << "numParty: " << nParties
				<< "  threshold: " << threshold
				<< "  setSize: " << setSize
				<< "  nTrials:" << nTrials << "\n";

		if (myIdx == 0)
		{
			std::cout << "Client Idx: " << myIdx << "\n";
			runtime << "Client Idx: " << myIdx << "\n";
			runtime	<< "Client Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
					<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n";
		}
		else
		{
			std::cout << "Leader Idx: " << myIdx << "\n";
			osuCrypto::Log::out << "#Output Intersection: " << num_intersection << osuCrypto::Log::endl;
			osuCrypto::Log::out << "#Expected Intersection: " << expected_intersection << osuCrypto::Log::endl;

			runtime << "Leader Idx: " << myIdx << "\n";
			runtime << "#Output Intersection: " << num_intersection << "\n";
			runtime << "#Expected Intersection: " << expected_intersection << "\n";
			runtime	<< "Leader Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
					<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n";

			std::string filename = "time_leader_MT.txt";
			std::ofstream oFile;
			oFile.open(filename, std::ios::out | std::ios::app);
			oFile << "************************************* \n"
				  << "numParty: " << nParties << " "
				  << "threshold: " << threshold << " "
				  << "setSize: " << setSize << "\n"
				  << "share time: " << totalAvgShareTime << " s\n"
				  << "total_share_sd: " << total_share_sd << " s\n"
				  << "recon time: " << totalAvgReconTime << " s\n"
				  << "total_recon_sd: " << total_recon_sd << " s\n"
				  << "Total time: " << totalAvgTime << " s\n"
				  << "total_sd: " << total_sd << " s\n"
				  << "------------------\n";
		}

		std::cout << "numParty: " << nParties
				  << "  threshold: " << threshold
				  << "  setSize: " << setSize
				  << "  nTrials:" << nTrials << "\n"

				  << "Total time: " << totalAvgTime << " s\n"
				// << "total_sd: " << total_sd << " s\n"
				//   << "share time: " << totalAvgShareTime << " s\n"
				// <<"total_share_sd: " << total_share_sd<< " s\n"
				//   << "recon time: " << totalAvgReconTime << " s\n"
				// << "total_recon_sd: "<< total_recon_sd<< " s\n"
				//   << "phase1 time: " << totalAvgPhase1Time << " ms\n"
				//   << "phase2 time: " << totalAvgPhase2Time << " ms\n"
				//   << "phase3 time: " << totalAvgPhase3Time << " ms\n"
				//   << "phase4 time: " << totalAvgPhase4Time << " ms\n"
				  << "------------------\n";

		runtime << "numParty: " << nParties
				<< "  threshold: " << threshold
				<< "  setSize: " << setSize
				<< "  nTrials:" << nTrials << "\n"

				<< "Total time: " << totalAvgTime << " s\n"
				<< "total_sd: " << total_sd << " s\n"

				// << "share time: " << totalAvgShareTime << " s\n"
				// <<"total_share_sd: " << total_share_sd<< " s\n"

				// << "recon time: " << totalAvgReconTime << " s\n"
				// << "total_recon_sd: "<< total_recon_sd<< " s\n"

				<< "phase1 time: " << totalAvgPhase1Time << " ms\n"
				<< "phase2 time: " << totalAvgPhase2Time << " ms\n"
				<< "phase3 time: " << totalAvgPhase3Time << " ms\n"
				<< "phase4 time: " << totalAvgPhase4Time << " ms\n"
				
				<< "------------------\n";


		runtime.close();
	}

	// for (u64 i = 0; i < nParties; ++i)
	// {
	// 	if (i != myIdx)
	// 	{
	// 		for (u64 j = 0; j < numThreads; ++j)
	// 		{
	// 			chlsOLE[i][j].close();
	// 		}
	// 	}
	// }
	// //  std::cout<<"Idx = " << myIdx <<" 111"<< std::endl;
	// for (u64 i = 0; i < nParties; ++i)
	// {
	// 	if (i != myIdx)
	// 		epOLE[i].stop();
	// }

	// iosOLE.stop();

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}

	ios.stop();
}
