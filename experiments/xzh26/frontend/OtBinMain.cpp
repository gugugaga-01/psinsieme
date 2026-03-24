#include "Network/BtEndpoint.h"  //cryptoTools

#include "OPPRF/OPPRFReceiver.h" //libOPRF->frontend
#include "OPPRF/OPPRFSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "Common/Defines.h"
//#include "NChooseOne/KkrtNcoOtReceiver.h" //libOTe
//#include "NChooseOne/KkrtNcoOtSender.h"

//#include "NChooseOne/Oos/OosNcoOtReceiver.h" //libOTe
//#include "NChooseOne/Oos/OosNcoOtSender.h"
#include "Common/Log.h"  //cryptoTools
#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <numeric>
#include <iostream>
#include "OtBinMain.h"

#include "utils/bloom_filter.h" //frontend
#include "utils/common.h"
#include <chrono>
#include <array>
#include <cstring>
#include <sodium.h>

//typedef std::pair<NTL::ZZ, NTL::ZZ> Ciphertext;
//using ECpoint = std::array<unsigned char, crypto_core_ristretto255_BYTES>;
//using Ciphertext = std::pair<ECpoint, ECpoint>;

// 标量类型
//using ECscalar = std::array<unsigned char, crypto_core_ristretto255_SCALARBYTES>;

// 定义单位元（0 元素）即O
//const ECpoint ZERO_POINT = {0};  // 全0数组，加法单位元

#define ZZtoBytesSize 256

const size_t SEED_BYTES = 16;

//std::vector<NTL::ZZ> get_factors(const NTL::ZZ& p) {
//    std::vector<NTL::ZZ> factors;
//    factors.push_back(NTL::ZZ(2)); 
//    NTL::ZZ large_prime = (p - 1) / 2;
//    factors.push_back(large_prime);
//    return factors;
//}
//gcd(k,p) ?= 1
//bool CoprimeWithP(const NTL::ZZ &k, const NTL::ZZ &p)
//{
//    std::vector<NTL::ZZ> factors;
//    factors = get_factors(p);
//    for (const NTL::ZZ& factor : factors)
//    {
//        if(k % factor == 0 || factor % k == 0)
//        {
//            return false;
//        }
//    }
//    return true;
//}

//void Encrypt(Ciphertext &ciphertext, const NTL::ZZ &plaintext, NTL::ZZ alpha, NTL::ZZ beta, NTL::ZZ p) 
//{
//  NTL::ZZ random_num;
//  RandomBnd(random_num, p);
  // gcd(random_num,p-1) = 1 & (3<=random_num <=p-2)
//  while (!CoprimeWithP(random_num, p) || random_num < 3 || random_num > p - 1 ) 
//  {
//    random_num += 1;
//  }
//  PowerMod(ciphertext.first, alpha, random_num, p);
//  PowerMod(ciphertext.second, beta, random_num, p);
//  MulMod(ciphertext.second, ciphertext.second, plaintext, p);
//}

//ElGamal加密，B是公钥点
void Encrypt(Ciphertext &cipher, const ECpoint &plaintext, const ECpoint &B) 
{
    // 1. 生成随机标量 r
    ECscalar r = scalar_random();
    // 2. 计算 C1 = r * G
    cipher.first = scalar_mul_base(r);
    // 3. 计算临时值 temp = r * B
    ECpoint temp = scalar_mul(r, B);
    // 4. 计算 C2 = temp + plaintext
    cipher.second = point_add(temp, plaintext);
}

//void Mul(Ciphertext &dest, const Ciphertext &src1, const Ciphertext &src2, NTL::ZZ p)
//{
//  MulMod(dest.first, src1.first, src2.first, p);
//  MulMod(dest.second, src1.second, src2.second, p);
//}

// 密文同态加法：对应点相加
void Homo_Add(Ciphertext &dest, const Ciphertext &src1, const Ciphertext &src2) 
{
    dest.first = point_add(src1.first, src2.first);
    dest.second = point_add(src1.second, src2.second);
}


//void PartialDecrypt(NTL::ZZ &decryption_share, const NTL::ZZ &c1 , NTL::ZZ a, NTL::ZZ p)
//{
//  PowerMod(decryption_share, c1, -a, p);
//}

void PartialDecrypt(ECpoint &decryption_share, const ECpoint &c1, const ECscalar &a) {
    // 计算 neg_a = -a
    // 计算 share = neg_a * c1
    decryption_share = scalar_mul(scalar_negate(a), c1);
    
    // 注意：如果结果为单位元，scalar_mul会返回错误
    // 但在ElGamal解密中，这种情况概率极低
}

//void FullyDecrypt(NTL::ZZ &plaintext, const std::vector<NTL::ZZ> &decryption_shares, const NTL::ZZ &c2, NTL::ZZ p) 
//{
//  plaintext = c2;
//  for (const auto &it : decryption_shares) 
//  {
//    MulMod(plaintext, plaintext, it, p);
//  }
//}

void FullyDecrypt(ECpoint &plaintext, const std::vector<ECpoint> &decryption_shares, const ECpoint &c2) 
{
    // 初始化 plaintext = c2
    plaintext = c2;
    // 依次加上所有解密份额
    for (const auto &share : decryption_shares) {
        plaintext = point_add(plaintext, share);
    }
}

ECpoint block_to_point(const block &input) {
    // 1. 序列化block为字节数组（小端/大端均可，需保持一致性）
    unsigned char block_bytes[16];  // block是16字节
    memcpy(block_bytes, &input, 16);

    // SHA-512哈希
    unsigned char hash_64bytes[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash_64bytes, block_bytes, 16);

    // 映射到Ristretto255点
    ECpoint result_point;
    int ret = crypto_core_ristretto255_from_hash(result_point.data(), hash_64bytes);
    
    if (ret != 0) {
        std::cerr << "Error: block_to_ristretto_point failed!" << std::endl;
        return ZERO_POINT;
    }

    return result_point;
}

std::vector<ECpoint> setblock_to_points(const std::vector<block>& setBlock) {
    std::vector<ECpoint> points(setBlock.size());
    for (size_t i = 0; i < setBlock.size(); ++i) {
        points[i] = block_to_point(setBlock[i]);
    }
    return points;
}

/*void bytesToBlocks(const unsigned char* bytes, size_t length, std::vector<block>& blocks) 
{
	 if (length % 16 != 0) 
     {
        std::cout << "Error: Length is not a multiple of 16." << std::endl;
        return;
    }
    size_t numBlocks = length / 16;
    blocks.resize(numBlocks);

    for (size_t i = 0; i < numBlocks; ++i) 
    {
        blocks[i] = _mm_loadu_si128(reinterpret_cast<const block*>(bytes + i * 16));
    }
}//在OPPRF阶段调用

void blocksToBytes(const std::vector<block>& blocks, unsigned char* bytes) 
{
    size_t numBlocks = blocks.size();
    size_t bytesLength = numBlocks * sizeof(block);

    memcpy(bytes, blocks.data(), bytesLength);
}//在decrypt阶段调用，将解密份额转换为字节数组
*/



//leader is n-1
//myIdx: 当前参与方的索引（0 到 nParties-1）
//nParties: 总参与方数量
//setSize: 每个参与方的集合大小
//nTrials: 实验重复次数
void tparty(u64 myIdx, u64 nParties, u64 setSize, u64 nTrials)

{
    //初始化 libsodium
	if (sodium_init() < 0) {
        std::cerr << "Error: libsodium initialization failed" << std::endl;
        return;
    }
    //u64 opt = 0;
	std::fstream runtime;
	u64 leaderIdx = nParties - 1; //leader party

    std::string outputDir = "output";

	if (myIdx == 0)
		runtime.open("./runtime_client.txt", runtime.app | runtime.out);

	if (myIdx == leaderIdx)
		runtime.open("./runtime_leader.txt", runtime.app | runtime.out);
    //为客户端（myIdx=0）和 leader 分别打开运行时记录文件

#pragma region setup

    double totalTime = 0, totalAvgTime = 0;
    std::vector<double> eachTime(nTrials);
    double total_sd = 0;

	u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
		ss2DirAvgTime(0), ssRoundAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

	u64  psiSecParam = 40, bitSize = 256/* 128*/, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));
    //psiSecParam: PSI 安全参数（40位）
    //bitSize: 位大小（128位）
    //numThreads: 线程数（1）
    //prng: 伪随机数生成器，用 myIdx 作为种子确保不同参与方生成不同随机序列

	std::string name("psi");
	BtIOService ios(0);


	std::vector<BtEndpoint> ep(nParties);

	//创建通信信道
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}
    //建立与其他各方的点对点通信连接
    //端口号计算确保双向连接一致性

	std::vector<std::vector<Channel*>> chls(nParties);
	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;

		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
				//chls[i][j].mEndpoint;
				//myIdx->i


			}
		}
	}
    //为每个通信对端创建通道数组
    //dummy数组可能用于测试或标识


    u64 num_intersection;
	double dataSent, Mbps, MbpsRecv, dataRecv;
    //std::cout << "myIdx: " << myIdx << std::endl;
    //std::cout << "nParties: " << nParties << std::endl;
    //std::cout << "setSize: " << setSize << std::endl;
    //std::cout << "nTrials: " << nTrials << std::endl;
    //std::cout << "psiSecParam: " << psiSecParam << std::endl;
    //::cout << "setup completed" << std::endl;
    //统计变量声明
   

#pragma endregion

	//PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, nTrials));
	//PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));

    //其中Same使用固定种子，确保所有参与方生成相同的随机序列。
    //Diff的种子包含 myIdx，确保每个参与方生成不同的随机序列
	long expected_intersection;//期望的交集大小
	NTL::ZZ sameseed = NTL::conv<NTL::ZZ>(nTrials);
    //从 nTrials 转换的大整数种子，用于生成相同数据
	NTL::ZZ diffseed = NTL::conv<NTL::ZZ>(myIdx);
    //从 myIdx 转换的大整数种子，用于生成不同数据

    for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)//循环进行 nTrials 次实验
	{

#pragma region input
        // result.clear();
        // count = 0;

        std::vector<u32> set(setSize);//大小为 setSize的整数向量
		NTL::SetSeed(sameseed);
		NTL::RandomBnd(expected_intersection, setSize);
        //std::cout << "expected_intersection: " << expected_intersection << std::endl;
        //随机生成的交集大小（0 到 setSize-1）

        long random_num = 0;
		
		bool isFind;
		std::unordered_map<long, std::string> map;

        
        //使用同样的种子生成随机数，确保各参与方生成相同的元素
		//集合的前 expected_intersection 个元素
        for (auto i = 0; i < expected_intersection; i++) 
		{
			isFind = false;
			while (!isFind)
			{
				NTL::RandomBnd(random_num, elementTypeMax);
				std::unordered_map<long, std::string>::iterator it;
				if ((it = map.find(NTL::conv<long>(random_num))) == map.end())
				{
					map.insert(std::make_pair(NTL::conv<long>(random_num), "element"));
					set[i] = random_num;
					isFind = true;
				}
			}
    	}

        //使用不同的种子（包含 myIdx），确保各参与方生成不同元素
        //集合的后 setSize - expected_intersection个元素
        NTL::SetSeed(NTL::conv<NTL::ZZ>(diffseed));
    	for (u64 i = expected_intersection; i < setSize; i++) 
		{
			isFind = false;
			while (!isFind)
			{
				NTL::RandomBnd(random_num, elementTypeMax);
				std::unordered_map<long, std::string>::iterator it;
				if ((it = map.find(NTL::conv<long>(random_num))) == map.end())
				{
					map.insert(std::make_pair(NTL::conv<long>(random_num), "element"));
					set[i] = random_num;
					isFind = true;
				}

			}
   		}

        //std::cout << "input completed" << std::endl;
#pragma endregion

        u64 num_threads = nParties - 1;
        std::vector<std::thread>  pThrds(num_threads);
        //线程池，大小为参与方数减去1

        u64 opprfNum =/* 2048/128 * 2*/ 2 ; //Cipher size :2048bits + 2048bits
        //每对参与方之间要完成的OPPRF实例数量
		//std::vector<KkrtNcoOtReceiver> otRecv(nParties * opprfNum);
		//std::vector<KkrtNcoOtSender> otSend(nParties * opprfNum);
		std::vector<OPPRFSender> send(nParties * opprfNum);
		std::vector<OPPRFReceiver> recv(nParties * opprfNum);


        auto start = std::chrono::high_resolution_clock::now();

        binSet bins;
        
        //##########################
		//### Offline Phasing
		//##########################

        bins.init(myIdx, nParties, setSize, psiSecParam);//初始化Bins
		//u64 otCountSend = bins.mSimpleBins.mBins.size();//Simplehash桶数量
		//u64 otCountRecv = bins.mCuckooBins.mBins.size();//Cuckoohash桶数量
        //获取OT发送和接收的数量

        //########################## 
		//### Base OT阶段，修改为初始化OPRF实例
		//##########################

        std::vector<std::thread> otpThrds(nParties - 1);

		if (myIdx == leaderIdx)
        //Leader初始化OT实例
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
            //为nParties个Client各启动opprfNum个初始化
			{
				otpThrds[pIdx] = std::thread([&, pIdx]() { 
					for (u64 opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++)
                    //opprfNum个
					{
						u64 index = pIdx * opprfNum + opprfIdx;  
						recv[index].init(nParties, setSize, psiSecParam, chls[pIdx], ZeroBlock);

					}

				});
				
			}		
		}
        else
        //Client初始化OT实例，每个Client启动opprfNum次即可
		{
			otpThrds.resize(1);
			otpThrds[otpThrds.size() - 1] = std::thread([&, leaderIdx]() { 
				for (u64 opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++)
				{
					send[opprfIdx].init(nParties, setSize, psiSecParam, chls[leaderIdx], prng.get<block>());					
				}
			});	
			
		}
		for (u64 pIdx = 0; pIdx < otpThrds.size(); ++pIdx)
			otpThrds[pIdx].join();
        //启动OT线程
        auto otInitDone = std::chrono::high_resolution_clock::now();

        //std::cout << "OPPRFinit completed" << std::endl;
        
        
#pragma region DKG
        //椭圆曲线参数已经选定过了，使用Ristretto255群，无需计算参数
        //NTL::ZZ p = NTL::conv<NTL::ZZ> ("p");
		//NTL::ZZ alpha = NTL::conv<NTL::ZZ> ("alpha");
		//NTL::ZZ a(1);
        ECscalar a;  // 私钥份额
        

        //NTL::SetSeed(diffseed);

        // secret key a
        //NTL::RandomBnd(a, p - 1);
    	//while (a < 1) 
		//{
      	//	NTL::RandomBnd(a, p - 1);
     	//}
        a = scalar_random();
        //生成1到(p-1)的大整数私钥，每个参与方独立生成
        
        //NTL::ZZ betaPart;某方公钥份额
		//NTL::ZZ beta;联合公钥
		//NTL::PowerMod(betaPart, alpha, a, p);即betaPart = (alpha^a) mod p
        
        ECpoint betaPart;  //某方公钥份额
        ECpoint beta;  // 联合公钥
        betaPart = scalar_mul_base(a);

        //联合公钥计算belta= betaPart_0*...*betaPart_{n-1}聚合公钥
        if (myIdx != leaderIdx)
        //非Leader端(Client)与Leader交换公钥份额betaPart
		{
			auto &chl = *chls[leaderIdx][0];
            //初始化信道，这行没改

			//std::vector<NTL::ZZ> sendPay(1);
			//sendPay[0] = betaPart;
			//unsigned char buf[ZZtoBytesSize];
    		//BytesFromZZ(buf, sendPay[0], ZZtoBytesSize);
			//chl.asyncSend(&buf, ZZtoBytesSize);
            //发送本方的公钥份额
            chl.asyncSend(betaPart.data(), crypto_core_ristretto255_BYTES);

			//std::vector<NTL::ZZ> recvPay(1);
			//chl.recv(&buf, ZZtoBytesSize);
			//ZZFromBytes(recvPay[0], buf, ZZtoBytesSize);
			//beta = recvPay[0];
            //接收联合公钥
            unsigned char buf[crypto_core_ristretto255_BYTES];
            chl.recv(&buf, crypto_core_ristretto255_BYTES);
            memcpy(beta.data(), buf, crypto_core_ristretto255_BYTES);
		}
		else
        //Leader端收集所有Client的公钥份额
		{
			beta = betaPart;
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				auto &chl = *chls[pIdx][0];
				//std::vector<NTL::ZZ> recvPay(1);
				
				
				// std::cout<<"recv "<<recvPay[0]<<std::endl;
                //unsigned char buf[ZZtoBytesSize];
                unsigned char buf[crypto_core_ristretto255_BYTES];
                //chl.recv(&buf, ZZtoBytesSize);
                chl.recv(&buf, crypto_core_ristretto255_BYTES);
                ECpoint other_share;
                //ZZFromBytes(recvPay[0], buf, ZZtoBytesSize);
                memcpy(other_share.data(), buf, crypto_core_ristretto255_BYTES);
                //NTL::MulMod(beta, beta, recvPay[0], p);
                beta = point_add(beta, other_share);
			}
            //Leader端广播联合公钥beta给所有Client
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
			 	auto &chl = *chls[pIdx][0];
				//std::vector<NTL::ZZ> sendPay(1);
				//sendPay[0] = beta;
				//unsigned char buf[ZZtoBytesSize];
    			//BytesFromZZ(buf, sendPay[0], ZZtoBytesSize);
				//chl.asyncSend(&buf, ZZtoBytesSize);
                chl.asyncSend(beta.data(), crypto_core_ristretto255_BYTES);
	
			}
        }

        auto DKGDone = std::chrono::high_resolution_clock::now();
        //std::cout << "DKG completed" << std::endl;
#pragma endregion

#pragma region EBF

        std::vector<u32> murmurhashSeeds = {
		1805253736,
        397701183,
        1495055303,
        1012881222,
        1442197113,
        899180298,
        1148210001,
        1954046069,
        1587823014,
        121110290};
        //定义MurmurHash函数的种子，10个32位随机数

        double false_positive_rate = 0.001;
		double m = -(setSize * log(false_positive_rate)) / (log(2) * log(2));

        u32 bf_size = std::ceil(m);
        u64 hashNum = std::round(-std::log2(false_positive_rate));
        //计算布隆过滤器的位数m和实际大小bf_size，哈希函数的个数hashNum
		
		BloomFilter bf(bf_size, murmurhashSeeds);
        std::vector<Ciphertext> encrypted_bloom_filter(bf.size());
        //创建布隆过滤器对象和加密布隆过滤器
        //std::cout << "Leader: bf.size() = " << bf.size() 
          //<< ", encrypted_bloom_filter will be sized = " << bf.size() 
          //<< ", nParties-1 = " << nParties-1 
          //<< std::endl;

        //Leader端生成（加密）布隆过滤器
        if (myIdx == leaderIdx)
        {
            
            //EBF
            bf.Clear();
			for(const auto &e: set)
			{
				bf.Insert(e);
			}
            //std::cout << "EBF init completed" << std::endl;

            

            std::vector<std::thread>  pThrds(nParties - 1);
            int total_elements = bf.size();
            int elements_per_thread = total_elements / (nParties - 1);
            //std::cout << "Leader: EBF elements_per_thread = " << elements_per_thread << std::endl;

            for(u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
            {
                int start = pIdx * elements_per_thread;
                int end = (pIdx == nParties - 1 - 1) ? total_elements : (start + elements_per_thread);
                pThrds[pIdx] = std::thread([&, pIdx, start, end](){
                    for (int i = start; i < end; ++i) 
                    {
                        if (!bf.CheckPosition(i))
                        {
                            //encrypted_bloom_filter[i] = std::make_pair(RandomBnd(p - 1), RandomBnd(p - 1));
                            //位置为0，生成随机数填充
                            encrypted_bloom_filter[i] = std::make_pair(point_random(), point_random());
                        }
                        else
                        {
                            // auto  encrystart = std::chrono::high_resolution_clock::now();
                            //Encrypt(encrypted_bloom_filter[i], NTL::ZZ(1), alpha, beta, p);
                            
                            //位置为1，加密单位元
                            Encrypt(encrypted_bloom_filter[i], ZERO_POINT, beta);
                            //std::cout << "encrypt completed" << std::endl;
                            
                            // auto encryDone = std::chrono::high_resolution_clock::now();
                            // auto encr = std::chrono::duration_cast<std::chrono::microseconds>(encryDone - encrystart).count();
                            // std::cout<<"encr: "<< encr<<std::endl;
                        }
                    }

                });
            }

            for(size_t pIdx = 0; pIdx < pThrds.size(); ++pIdx)
            {
				pThrds[pIdx].join();
			}
        }

        auto EBFDone = std::chrono::high_resolution_clock::now();
        //std::cout << "EBF completed" << std::endl;

#pragma endregion


#pragma region sendEBF  

        if (myIdx == leaderIdx)
        //Leader端发送布隆过滤器给所有Client
        {
            std::vector<std::thread> pThrds(nParties - 1);

            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
		    {
                pThrds[pIdx]  = std::thread([&, pIdx](){

                    for (size_t i = 0; i < bf.size(); ++i) 
                    {
                        //unsigned char buf[2048/8];
                        //缓冲区
                        //unsigned char buf[crypto_core_ristretto255_BYTES];
        
                        //BytesFromZZ(buf, encrypted_bloom_filter[i].first, 2048/8);
                        //chls[pIdx][0]->send(&buf, 2048/8);
                        //先序列化到缓冲区buf中，再send发送，对于libsodium直接是char数组
                        chls[pIdx][0]->send(encrypted_bloom_filter[i].first.data(), crypto_core_ristretto255_BYTES);

                        //BytesFromZZ(buf, encrypted_bloom_filter[i].second, 2048/8);
                        //chls[pIdx][0]->send(&buf, 2048/8);
                        //同理发送第二个密文
                        chls[pIdx][0]->send(encrypted_bloom_filter[i].second.data(), crypto_core_ristretto255_BYTES);
                    }

                });
            }
            

            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
		    {
                pThrds[pIdx].join();
            }
        }
        else
        //Client端接收布隆过滤器
        {
            for (size_t i = 0; i < bf.size(); ++i) 
            {
                //unsigned char buf[2048/8];
                //缓冲区
                unsigned char buf[crypto_core_ristretto255_BYTES];

                //chls[leaderIdx][0]->recv(&buf, 2048/8);
                //ZZFromBytes(encrypted_bloom_filter[i].first, buf, 2048/8);
                //接收第一个密文
                chls[leaderIdx][0]->recv(&buf, crypto_core_ristretto255_BYTES);
                memcpy(encrypted_bloom_filter[i].first.data(), buf, crypto_core_ristretto255_BYTES);

                //chls[leaderIdx][0]->recv(&buf, 2048/8);
                //ZZFromBytes(encrypted_bloom_filter[i].second, buf, 2048/8);
                //接收第二个密文
                chls[leaderIdx][0]->recv(&buf, crypto_core_ristretto255_BYTES);
                memcpy(encrypted_bloom_filter[i].second.data(), buf, crypto_core_ristretto255_BYTES);

            }
        }

        auto SendEBFDone = std::chrono::high_resolution_clock::now();
        //std::cout << "SendEBF completed" << std::endl;
#pragma endregion


#pragma region Client_test

        std::vector<Ciphertext> encrypted_membership_test_results(setSize);
        if (myIdx != leaderIdx)
        //Client端进行布隆过滤器测试，查看自己的元素在EBF中对应的位置，得到结果数组
        {
            Ciphertext test_result;
            for (u64 i = 0; i < setSize; i++) 
            {
                auto positions = bf.GetPositions(set[i]);
                test_result = encrypted_bloom_filter[positions[0]];

                for (size_t j = 1; j < positions.size(); j++)
                {
                    //Mul(test_result, test_result, encrypted_bloom_filter[positions[j]], p);
                    Homo_Add(test_result, test_result, encrypted_bloom_filter[positions[j]]);
                }
                encrypted_membership_test_results[i] = test_result;

                //Ciphertext ones;
                //Encrypt(ones, NTL::ZZ(1), alpha, beta, p);
                //加密单位元
                Ciphertext zeros;
                Encrypt(zeros, ZERO_POINT, beta);

                //Mul(encrypted_membership_test_results[i], encrypted_membership_test_results[i], ones, p);
                //同态加单位元密文执行刷新操作
                Homo_Add(encrypted_membership_test_results[i], encrypted_membership_test_results[i], zeros);
            }
        }

        auto Client_testDone = std::chrono::high_resolution_clock::now();
        //std::cout << "Client_test completed" << std::endl;

#pragma endregion


#pragma region DH-OPPRF


        std::vector<block> setBlock(setSize);

		for (size_t i = 0; i < setBlock.size(); i++)
		{
			setBlock[i] = toBlock(set[i]);
		}
        //把set中的所有元素拉长，转换成block类型的setBlock
        //std::cout << "setBlock completed" << std::endl;


	    //##########################
		//### Hashing
		//##########################

        bins.hashing2Bins(setBlock, 1);
        //对集合元素进行哈希分桶，1指进程数
        //std::cout << "Hashing2Bins completed" << std::endl;

        std::vector<binSet> binSets;

        for (int i = 0; i < /*2048/128 * 2*/ 2/*opprfNum*/; i++)
		{
			binSet b = bins;
			binSets.push_back(b);
		}
        //std::cout << "binSet completed" << std::endl;
        //每个OPPRF使用一个同样的binSet（输入的u32的集合的的分桶结果），数量为opprfNum

        //#############################
        // DH-OPRF两轮通信计算得到OPRF值并存入哈希桶
        //#############################

        if (myIdx != leaderIdx) {
            // ========== 客户端（发送方）逻辑 ==========

            // 1. 生成DH私钥和公钥
            ECscalar priv_key = scalar_random();  // 随机私钥k

            // 2. 将自己的输入集合哈希到曲线点
            std::vector<ECpoint> hashedPoints = setblock_to_points(setBlock);
            

            // 3. 计算自己的OPRF值：F_k(x) = H(x)^k
            std::vector<ECpoint> myOPRFValues(setSize);
            for (size_t i = 0; i < setSize; ++i) {
                myOPRFValues[i] = scalar_mul(priv_key, hashedPoints[i]);
            }
            //std::cout << "client self OPPRFvalues completed" << std::endl;

            // 4. 接收领导者发送的盲化点Q=H(x')^r
            auto& chl = *chls[leaderIdx][0];
            std::vector<ECpoint> blindedPoints(setSize);
            for (size_t i = 0; i < setSize; ++i) {
                unsigned char buf[crypto_core_ristretto255_BYTES];
                chl.recv(&buf, crypto_core_ristretto255_BYTES);
                memcpy(blindedPoints[i].data(), buf, crypto_core_ristretto255_BYTES);
            }
            //std::cout << "client self blindedPoints completed" << std::endl;

            // 5. 处理盲化点：Q' = Q^k = H(x')^(r*k)
            std::vector<ECpoint> processedPoints(setSize);
            for (size_t i = 0; i < setSize; ++i) {
                processedPoints[i] = scalar_mul(priv_key, blindedPoints[i]);
            }
            //std::cout << "client self processedPoints completed" << std::endl;

            // 6. 发送处理后的点回给领导者
            for (size_t i = 0; i < setSize; ++i) {
                chl.asyncSend(processedPoints[i].data(), crypto_core_ristretto255_BYTES);
            }
            //std::cout << "client self send processedPoints completed" << std::endl;

            // 7. 将计算好的OPRF值填充到OPPRF中，完成getOPRFkeys步骤
            send[0].getOPRFkeysSeperatedandTable(leaderIdx, binSets[0], myOPRFValues);
            send[1].getOPRFkeysSeperatedandTable(leaderIdx, binSets[1], myOPRFValues);
            //std::cout << "DH-OPPRFClient completed" << std::endl;
        }
        else
        // ========== 领导者（接收方）逻辑 ==========
        {
            // 1. 创建一个向量用于存储每个客户端的处理后的点
            std::vector<std::vector<ECpoint>> processedPointsFromClients(nParties - 1);
            
            // 2. 将自己的输入集合哈希到曲线点
            std::vector<ECpoint> hashedPoints = setblock_to_points(setBlock);
            
            // 为每个客户端生成随机盲化因子并计算盲化点
            std::vector<std::vector<ECscalar>> blindFactors(nParties - 1);
            std::vector<std::vector<ECpoint>> blindedPoints(nParties - 1);
            //std::cout << "leader blindFactors init completed" << std::endl;
            
            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx) {
                blindFactors[pIdx].resize(setSize);
                blindedPoints[pIdx].resize(setSize);
                
                // 为每个输入生成随机盲化因子
                for (size_t i = 0; i < setSize; ++i) {
                    // 生成随机标量作为盲化因子
                    blindFactors[pIdx][i] = scalar_random();
                    // 计算盲化点：Q = H(x)^r
                    blindedPoints[pIdx][i] = scalar_mul(blindFactors[pIdx][i], hashedPoints[i]);
                }
            }
            //std::cout << "leader blindedPoints completed" << std::endl;
            
            // 3. 发送盲化点给对应的客户端
            std::vector<std::thread> sendThreads(nParties - 1);
            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx) {
                sendThreads[pIdx] = std::thread([&, pIdx]() {
                    auto& chl = *chls[pIdx][0];
                    for (size_t i = 0; i < setSize; ++i) {
                        chl.asyncSend(blindedPoints[pIdx][i].data(), 
                                    crypto_core_ristretto255_BYTES);
                    }
                });
            }
            for (auto& t : sendThreads) t.join();
            //std::cout << "leader send blindedPoints completed" << std::endl;
            
            // 4. 接收所有客户端处理后的点
            std::vector<std::thread> recvThreads(nParties - 1);
            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx) {
                recvThreads[pIdx] = std::thread([&, pIdx]() {
                    auto& chl = *chls[pIdx][0];
                    processedPointsFromClients[pIdx].resize(setSize);
                    for (size_t i = 0; i < setSize; ++i) {
                        unsigned char buf[crypto_core_ristretto255_BYTES];
                        chl.recv(&buf, crypto_core_ristretto255_BYTES);
                        memcpy(processedPointsFromClients[pIdx][i].data(), buf, 
                            crypto_core_ristretto255_BYTES);
                    }
                });
            }
            for (auto& t : recvThreads) t.join();
            //std::cout << "leader recv processedPoints completed" << std::endl;
            
            // 5. 计算最终的OPRF值：F_k(x) = (Q')^(1/r) = H(x)^k
            // 为每个客户端计算对应的OPRF值
            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx) {
                std::vector<ECpoint> myOPRFValues(setSize);
                
                for (size_t i = 0; i < setSize; ++i) {
                    // 计算盲化因子的逆
                    ECscalar inv_blind = scalar_invert(blindFactors[pIdx][i]);
                    // 计算最终OPRF值
                    myOPRFValues[i] = scalar_mul(inv_blind, processedPointsFromClients[pIdx][i]);
                }
                //std::cout << "leader OPRFkeys compute completed" << std::endl;

                // 6. 将计算好的OPRF值填充到对应的OPPRF实例中
                u64 index = pIdx * opprfNum;  // 每个客户端有opprfNum个实例
                recv[index].getOPRFkeysSeperatedandTable(pIdx, binSets[0], myOPRFValues);
                recv[index + 1].getOPRFkeysSeperatedandTable(pIdx, binSets[1], myOPRFValues);
            }
            //std::cout << "DH-OPPRF Leader completed" << std::endl;
        }
        //std::cout << "DH_OPRF completed" << std::endl;
        // //##########################
		// //### Online Phasing - compute OPRF
		// //##########################


        /*otpThrds.resize(nParties - 1);

        if (myIdx == leaderIdx)
        //Leader生成OPPRF密钥
        {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
            {
                otpThrds[pIdx] = std::thread([&, pIdx]() { 
     				for (u64 opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++)
     				{	
      					u64 index = pIdx * opprfNum + opprfIdx;  
      					recv[index].getOPRFkeysSeperatedandTable(pIdx, binSets[opprfIdx], chls[pIdx], false);
     				}

    			});
            }
        }
        else
        //Client端生成OPPRF密钥
        {
   		    otpThrds.resize(1);
   		    otpThrds[otpThrds.size() - 1] = std::thread([&, leaderIdx]() { 
    		    for (u64 opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++)
    		    {
     			    send[opprfIdx].getOPRFkeysSeperatedandTable(leaderIdx, binSets[opprfIdx], chls[leaderIdx], false);
   	 		    }
   		    }); 
   
  	    }
  	    for (u64 pIdx = 0; pIdx < otpThrds.size(); ++pIdx)
   	        otpThrds[pIdx].join();*/

        //##########################
		//### online phasing - OPPRF
		//##########################


        //std::vector<std::vector<block>> firstBlock(2048/128, std::vector<block>(setSize));
        std::vector<ECpoint> firstPoint(setSize);
        std::vector<ECpoint> secondPoint(setSize);
		//std::vector<std::vector<block>> secondBlock(2048/128, std::vector<block>(setSize));
        //第一块密文和第二块密文使用的存储块
		//std::vector<std::vector<std::vector<block>>> totalData(nParties - 1);
        std::vector<std::vector<std::vector<ECpoint>>> totalData(nParties - 1);

		std::vector<Ciphertext> recvResult(setSize);
        //用于聚合所有密文的数组
		for (size_t i = 0; i < recvResult.size(); i++)
		{
			//recvResult[i].first = NTL::ZZ(1);
            recvResult[i].first = ZERO_POINT;
			//recvResult[i].second = NTL::ZZ(1);
            recvResult[i].second = ZERO_POINT;
		}//初始化


        //ZZ->block

        /*if(myIdx != leaderIdx)
        //Client端准备OPPRF的输入，编辑first和second Block
        {
            for (int j = 0; j < setSize; j++)
            {
                unsigned char first[2048/8];
			    unsigned char second[2048/8];

                BytesFromZZ(first, encrypted_membership_test_results[j].first, 2048/8);
                BytesFromZZ(second, encrypted_membership_test_results[j].second, 2048/8);


                std::vector<block> temp1;
                bytesToBlocks(first, sizeof(first), temp1); 

                std::vector<block> temp2;
                bytesToBlocks(second, sizeof(second), temp2);

                for (int i = 0; i < 2048/128; i++)
                {
                    firstBlock[i][j] = temp1[i];
                    secondBlock[i][j] = temp2[i];
                } 

            }
        }*/
        if(myIdx != leaderIdx)
        //Client端准备OPPRF的输入，编辑firstPoint和secondPoint
        {
            for (size_t j = 0; j < setSize; j++)
            {
                // 将加密的成员测试结果的两个ECpoint分别存入firstPoint和secondPoint
                firstPoint[j] = encrypted_membership_test_results[j].first;
                secondPoint[j] = encrypted_membership_test_results[j].second;
                //std::cout << "client OPPRF input completed" << std::endl;
            }
        }
        


        otpThrds.resize(nParties - 1);
        //OPPRF在线传输阶段

        if (myIdx == leaderIdx)
        //Leader端得到自己的查询值，存入totalData
		{
			for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
			{
				otpThrds[pIdx] = std::thread([&, pIdx]() { 

					//std::vector<std::vector<block>> recvTemp;
                    std::vector<std::vector<ECpoint>> recvTemp;
					for (u64 opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++)
					{
						u64 index = pIdx * opprfNum + opprfIdx;  
						//std::vector<block> recvBlock(setSize);
                        std::vector<ECpoint> recvPoint(setSize);
                        //std::cout << "Leader OPPRF recvPoint init completed" << std::endl;
						//recv[index].recvSSTableBased(pIdx, binSets[opprfIdx], recvBlock, chls[pIdx]);
                        recv[index].recvSSTableBased(pIdx, binSets[opprfIdx], recvPoint, chls[pIdx]);
						//recvTemp.push_back(recvBlock);
                        recvTemp.push_back(recvPoint);
					}
					totalData[pIdx] = recvTemp;
                    //std::cout << "Leader OPPRF recvTemp completed" << std::endl;
				});
						
			}		
		}
        else
        //将firstBlock和secondBlock作为OPPRF输入，发送给Leader端
        {
            otpThrds.resize(1);
			otpThrds[otpThrds.size() - 1] = std::thread([&, leaderIdx]() { 
				/*for (u64 opprfIdx = 0; opprfIdx < opprfNum; opprfIdx++)
				{
					if (opprfIdx < 2048/128 1)
					{
						
						send[opprfIdx].sendSSTableBased(leaderIdx, binSets[opprfIdx], firstBlock[opprfIdx], chls[leaderIdx]);
					
					}
					else
						send[opprfIdx].sendSSTableBased(leaderIdx, binSets[opprfIdx], secondBlock[opprfIdx - 2048/1281], chls[leaderIdx]);			
				}*/
                //std::cout << "Client OPPRF sendPoint init start" << std::endl;
                send[0].sendSSTableBased(leaderIdx, binSets[0], firstPoint, chls[leaderIdx]);
                send[1].sendSSTableBased(leaderIdx, binSets[1], secondPoint, chls[leaderIdx]);
                //std::cout << "Client OPPRF sendPoint completed" << std::endl;
			});	
        }

        for (u64 pIdx = 0; pIdx < otpThrds.size(); ++pIdx)
			otpThrds[pIdx].join();

        auto OPPRFDone = std::chrono::high_resolution_clock::now();
        //std::cout << "OPPRF completed" << std::endl;

#pragma endregion

#pragma region decrypt
//##########################
//### online phasing - decrypt
//##########################

        if (myIdx == leaderIdx)
        //从totalData中取出数据，计算得到recvResult数组
        {
            for (u64 pIdx = 0; pIdx < nParties - 1; pIdx++)
            //每个参与方都对recvResult数组进行一次操作，把自己的每个元素的密文传入recvResult
            {
                std::vector<block> temp(2048/128);
                for (u64 eIdx = 0; eIdx < setSize; eIdx++)
                //聚合所有参与方每个元素对应的密文，recvResult[eIdx]是第eIdx个元素对应的密文
                {
                    /*处理OPPRF输出的密文C_1
                    for (u64 row = 0; row < 2048/128; row++)
					{
						temp[row] = totalData[pIdx][row][eIdx];
					}

					unsigned char buf[2048/8];
					blocksToBytes(temp, buf);
					NTL::ZZ Tempzz;
					ZZFromBytes(Tempzz, buf, ZZtoBytesSize);
                    //Tempzz和buf作为缓冲区，其他两行是接收步骤

					MulMod(recvResult[eIdx].first, recvResult[eIdx].first, Tempzz, p);

                    //处理OPPRF输出的密文C_2
                    for (u64 row = 2048/128; row < 2048/128 * 2opprfNum ; row++)
					{
						temp[row - 2048/128] = totalData[pIdx][row][eIdx];
					}
				
					blocksToBytes(temp, buf);
					ZZFromBytes(Tempzz, buf, ZZtoBytesSize);

					MulMod(recvResult[eIdx].second, recvResult[eIdx].second, Tempzz, p);
					//Homo_Add();
                    */
                    //处理OPPRF输出的密文C_1
                    recvResult[eIdx].first = point_add(recvResult[eIdx].first, totalData[pIdx][0][eIdx]);

                    //处理OPPRF输出的密文C_2
                    recvResult[eIdx].second = point_add(recvResult[eIdx].second, totalData[pIdx][1][eIdx]);
        
                }
            }
            //recvResult数组到这里已经存储了n-1个客户端的setSize个密文聚合结果。
        }

        auto OPPRFoutProcessDone = std::chrono::high_resolution_clock::now();


        //send C_1 for decrypt
        if (myIdx == leaderIdx)
        //Leader端分线程给所有参与方发送C_1，请求协同解密
        {
            std::vector<std::thread>  pThrds(nParties - 1);

            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
            {
                pThrds[pIdx] = std::thread([&, pIdx]() {

                    for (size_t j = 0; j < setSize; ++j)
                    {
                        //unsigned char buf[2048/8];
                        //BytesFromZZ(buf, recvResult[j].first, 2048/8);
                        //chls[pIdx][0]->send(&buf, 2048/8);
                        chls[pIdx][0]->send(recvResult[j].first.data(), crypto_core_ristretto255_BYTES);
                    }

                });
            }

            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
            {
                pThrds[pIdx].join();
            }
        }
        else
        //Client端接收C_1
        {
            for (size_t i = 0; i < setSize; ++i) 
            {
                //unsigned char buf[2048/8];
                unsigned char buf[crypto_core_ristretto255_BYTES];
				//chls[leaderIdx][0]->recv(&buf, 2048/8);
                chls[leaderIdx][0]->recv(&buf, crypto_core_ristretto255_BYTES);
				//ZZFromBytes(recvResult[i].first, buf, 2048/8);
                memcpy(recvResult[i].first.data(), buf, crypto_core_ristretto255_BYTES);
            }
        }

        auto SendCipherDone = std::chrono::high_resolution_clock::now();



        //std::vector<NTL::ZZ>  local_partial_decryption(setSize);
        //部分解密结果的数组
        std::vector<ECpoint> local_partial_decryption(setSize);
        

        if(myIdx == leaderIdx)
        //Leader端完成部分解密
        {
            int thread_num = (setSize > nParties - 1) ? setSize : nParties - 1;
            std::vector<std::thread>  depThrds(thread_num);

            int total_elements = setSize;
	        int elements_per_thread = total_elements / thread_num;

            for(u64 i = 0; i < depThrds.size(); ++i)
            {
                int start = i * elements_per_thread;
                int end = (i == thread_num - 1) ? total_elements : (start + elements_per_thread);

                depThrds[i] = std::thread([&, i, start, end]() {

			        for (int j = start; j < end; ++j) 
                    {
			        	//PartialDecrypt(local_partial_decryption[j], recvResult[j].first, a, p);
                        //部分解密函数
                        PartialDecrypt(local_partial_decryption[j], recvResult[j].first, a);
			        }
		        });
            }

            for(size_t i = 0; i < depThrds.size(); ++i)
            {
			    depThrds[i].join();
            }
        }
        else
        //Client端完成部分解密
        {
            for (size_t j = 0; j < setSize; ++j) 
            {
			    //PartialDecrypt(local_partial_decryption[j], recvResult[j].first, a, p);
                //部分解密函数
                PartialDecrypt(local_partial_decryption[j], recvResult[j].first, a);
			}
        }

        auto PartDecryptDone = std::chrono::high_resolution_clock::now();
        //std::cout << "part decrypt completed" << std::endl;

        //std::vector<std::vector<NTL::ZZ>>  partial_decryption(setSize, std::vector<NTL::ZZ>(nParties));
        //二维数组，存储所有参与方的部分解密结果
        std::vector<std::vector<ECpoint>>  partial_decryption(setSize, std::vector<ECpoint>(nParties));

        if(myIdx == leaderIdx)
        //Leader从各Client接收部分解密结果
        {
            std::vector<std::thread>  pThrds(nParties - 1);

            for (u64 pIdx = 0; pIdx < nParties - 1; ++pIdx)
            //每个参与方传一次
		    {
                pThrds[pIdx] = std::thread([&](int pIdxCopy) {
                    for(u64 i = 0; i < setSize; ++i)
                    //每个元素传递到对应位置
                    {
                        //unsigned char buf[2048/8];
                        //缓冲区
                        unsigned char buf[crypto_core_ristretto255_BYTES];
                        //chls[pIdxCopy][0]->recv(&buf, 2048/8);
                        //NTL::ZZ temp;
                        //缓冲区
                        //ZZFromBytes(temp, buf, 2048/8);
                        //partial_decryption[i][pIdxCopy] = temp;
                        //转化并赋值
                        chls[pIdxCopy][0]->recv(&buf, crypto_core_ristretto255_BYTES);
                        memcpy(partial_decryption[i][pIdxCopy].data(), buf, crypto_core_ristretto255_BYTES);
                    }
                }, pIdx);
            }

            for(u64 i = 0; i < pThrds.size(); ++i)
            {
				pThrds[i].join();
			}

        }
        else
        //Client发送部分解密结果给Leader
        {
            for (size_t i = 0; i < setSize; ++i) 
            {
                //unsigned char buf[2048/8];
                //BytesFromZZ(buf, local_partial_decryption[i], 2048/8);
                //chls[leaderIdx][0]->send(&buf, 2048/8);
                //发送部分解密结果
                chls[leaderIdx][0]->send(local_partial_decryption[i].data(), crypto_core_ristretto255_BYTES);
            }
        }

        auto SendDecryResDone = std::chrono::high_resolution_clock::now();
        //std::cout << "decry completed" << std::endl;


        
#pragma endregion

#pragma region intersection
        //**********Fulldecrypt***********/
        std::vector<int> result(setSize);
        
        //这里能改成bool的vector吗？
        
        int count = 0;
        //结果变量

        if(myIdx == leaderIdx)
        //Leader端进行全解密
        {
            for (size_t i = 0; i < setSize; i++)
            //添加Leader的部分解密结果
            {
                partial_decryption[i][nParties - 1] = local_partial_decryption[i];
                //数据类型改变，这里不用修改
            }
            int thread_num = (setSize > nParties - 1) ? setSize : nParties - 1;
            std::vector<std::thread>  pThrds(thread_num);
            int total_elements = setSize;
    	    int elements_per_thread = total_elements /thread_num;
            //多线程完成完全解密任务

            for(u64 i = 0; i < pThrds.size(); ++i)
            {
                int start = i * elements_per_thread;
        	    int end = (i == thread_num - 1) ? total_elements : (start + elements_per_thread);

                pThrds[i] = std::thread([&, i, start, end]()
                {
                    for (int j = start; j < end; ++j) 
                    {
                        //NTL::ZZ res;
				        //FullyDecrypt(res, partial_decryption[j], recvResult[j].second, p);
                        //完全解密
                        ECpoint res;
                        FullyDecrypt(res, partial_decryption[j], recvResult[j].second);

                        //if(res == 1)
                        //解密结果是单位元吗
                        if(is_identity(res))
                        {
                            result[j] = 1;
                        }
                    }
                });

            }

            for(size_t i = 0; i < pThrds.size(); ++i)
            {
                pThrds[i].join();
		    }


            for (size_t i = 0; i < result.size(); i++)
            //统计标记为交集元素的结果，原来是解密为1，现在是解密为单位元
            {
                if (result[i] == 1)
                {
                    count++;
                }   
            }
            //std::cout<<"completed" <<std::endl;
            
            std::cout<<"expection_intersection: " << expected_intersection<<std::endl;
            std::cout<<"actual_intersection: "<<count<<std::endl;
            //输出期望交集和实际交集大小，验证协议正确性

        }

#pragma endregion

        auto IntersectionDone = std::chrono::high_resolution_clock::now();


        auto otInit = std::chrono::duration_cast<std::chrono::milliseconds>(otInitDone - start).count();

		auto DKG = std::chrono::duration_cast<std::chrono::milliseconds>(DKGDone - otInitDone).count();

		auto EBF = std::chrono::duration_cast<std::chrono::milliseconds>(EBFDone - DKGDone).count();

		auto SendEBF = std::chrono::duration_cast<std::chrono::milliseconds>(SendEBFDone - EBFDone).count();
        
        auto Client_test = std::chrono::duration_cast<std::chrono::milliseconds>(Client_testDone - SendEBFDone).count();

        auto OPPRF = std::chrono::duration_cast<std::chrono::milliseconds>(OPPRFDone - Client_testDone).count();

        auto OPPRFoutProcess = std::chrono::duration_cast<std::chrono::milliseconds>(OPPRFoutProcessDone - OPPRFDone).count();

        auto SendCipher = std::chrono::duration_cast<std::chrono::milliseconds>(SendCipherDone - OPPRFoutProcessDone).count();

        auto PartDecrypt = std::chrono::duration_cast<std::chrono::milliseconds>(PartDecryptDone - SendCipherDone).count();

        auto SendDecryRes = std::chrono::duration_cast<std::chrono::milliseconds>(SendDecryResDone - PartDecryptDone).count();
        
        auto Intersection = std::chrono::duration_cast<std::chrono::milliseconds>(IntersectionDone - SendDecryResDone).count();

        // auto total_time = otInit + DKG + EBF + SendEBF + Client_test + OPPRF + OPPRFoutProcess + SendCipher + PartDecrypt + SendDecryRes +  Intersection;

        // std::cout<<"P" <<myIdx << "'s total time =  "<<total_time<<std::endl;
        //时间统计阶段

        if (myIdx == leaderIdx || myIdx == 0) 
        {
            double time;
            std::string filename;
            if (myIdx == leaderIdx)
            {
                filename = outputDir + "/output_" + "leader.txt";
                time = otInit + EBF + SendEBF * 1.0 / (nParties - 1) + Client_test + OPPRF + OPPRFoutProcess + SendCipher * 1.0 / (nParties - 1) + PartDecrypt + SendDecryRes +  Intersection;

            }
            else
            {
                filename = outputDir + "/output_" + "client.txt";
                time = otInit + Client_test + OPPRF + PartDecrypt;
            }
            //根据角色计算总时间

            time /= 1000;

            eachTime[idxTrial] = time;

            totalTime += time;
            //时间单位转换和存储


            dataSent = 0;
            //总发送字节
			dataRecv = 0;
            //总接收字节
			Mbps = 0;
            //发送带宽
			MbpsRecv = 0;
            //接收带宽
			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dataRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}//统计发送和接收总字节数

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataRecv * 8 / time / (1 << 20);
            std::cout << "Mbps: " << Mbps << " MbpsRecv: " << MbpsRecv << std::endl;
            //计算总平均带宽

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}
            //重置通信统计，为下次实验做准备
            
            std::ofstream outfile(filename,std::ios::out|std::ios::app);
            //结果输出到文件

            if (outfile.is_open()) //filename,std::ios::out|std::ios::app
            {
                outfile <<"*********************\n"
                        <<"numParty: "<< nParties << " "
                        << "setSize: " << setSize << "\n"
                        << "Expected Intersection: " << expected_intersection << "\n"
                        << "Output Intersection: " << count << "\n"
                        <<"*********************\n"
                        << "otInit: " << otInit <<"\n"
                        << "DKG: " << DKG <<"\n"
                        << "EBF: " << EBF << "\n"
                        << "SendEBF: "<< SendEBF << "\n"
                        << "Client_test: "<< Client_test <<"\n"
                        << "OPPRF: "<<OPPRF<<"\n"
                        << "OPPRFoutProcess: " << OPPRFoutProcess <<"\n"
                        << "SendCipher: "<< SendCipher<< "\n"
                        << "PartDecrypt: "<< PartDecrypt << "\n"
                        << "SendDecryRes: " << SendDecryRes << "\n"
                        << "Intersection: "<<Intersection<<"\n"
                        <<"-------------------------------\n"
                        << "total_time: "<<time<<"\n"
                        // << "*********************\n";
                        << "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
				        << "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
				        << "------------------\n";
            }
        }   
    }
    //nTrials的循环结束



    if (myIdx == 0 || myIdx == leaderIdx) 
    {
        totalAvgTime = totalTime / nTrials;
        for(u64 i = 0; i < nTrials ; i++)
        {
            total_sd += pow(eachTime[i] - totalAvgTime, 2);
        }

        total_sd = sqrt(total_sd / nTrials);
        //计算平均时间totalAvgTime和标准差total_sd


        if (myIdx == 0)
		{
			std::cout << "Client Idx: " << myIdx << "\n";
			runtime << "Client Idx: " << myIdx << "\n";

		}
		else
		{
			std::cout << "Leader Idx: " << myIdx << "\n";
            runtime << "Leader Idx: " << myIdx << "\n";
        }


        std::cout << "numParty: " << nParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"

			<< "Total time: " << totalAvgTime << " s\n"
			<< "total_sd: " << total_sd << " s\n"
          <<"*********************\n";

        runtime << "numParty: " << nParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"

			<< "Total time: " << totalAvgTime  << " s\n"
			<< "total_sd: " << total_sd << " s\n"
            <<"*********************\n";

			runtime.close();
    }
    //将总体统计输出到控制台和运行时文件


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
    //关闭所有通信信道，停止服务
   
}
//tparty函数结束