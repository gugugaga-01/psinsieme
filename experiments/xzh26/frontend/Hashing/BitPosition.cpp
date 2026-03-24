#include "BitPosition.h"
#include "Crypto/sha1.h"
#include "Crypto/PRNG.h"
#include <random>
#include <algorithm>
#include "Common/Log.h"
#include "Common/Log1.h"
#include <numeric>


namespace osuCrypto
{
	block extractBlockFromECpoint(const ECpoint& point, int blockIndex) 
	{
        block result = ZeroBlock;
        if (blockIndex == 0) {
            // 提取前 16 字节
            memcpy(&result, point.data(), 16);
        } else {
            // 提取后 16 字节
            memcpy(&result, point.data() + 16, 16);
        }
        return result;
    }
	
	//int isSet(block & v, int n)
	//{
		//__m128i chkmask = _mm_slli_epi16(_mm_set1_epi16(1), n & 0xF);
		//int     movemask = (1 << (n >> 3));
		//int     isSet = (((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_and_si128(chkmask, v), _mm_setzero_si128())) & movemask) ^ movemask));
		//return isSet;
		//检查某位是否是1
	//}
	int isSet(ECpoint& v, int n)
    {
        // ECpoint 是 32 字节 (256 位)，我们需要确定 n 在哪个 128 位块中
        if (n < 128) {
            // 在前 16 字节中
            block blk = extractBlockFromECpoint(v, 0);
            __m128i chkmask = _mm_slli_epi16(_mm_set1_epi16(1), n & 0xF);
            int     movemask = (1 << (n >> 3));
            int     isSetResult = (((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_and_si128(chkmask, blk), _mm_setzero_si128())) & movemask) ^ movemask));
            return isSetResult;
        } else {
            // 在后 16 字节中，调整 n
            n = n - 128;
            block blk = extractBlockFromECpoint(v, 1);
            __m128i chkmask = _mm_slli_epi16(_mm_set1_epi16(1), n & 0xF);
            int     movemask = (1 << (n >> 3));
            int     isSetResult = (((_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_and_si128(chkmask, blk), _mm_setzero_si128())) & movemask) ^ movemask));
            return isSetResult;
        }
    }
	void setBit(block & v, int pos)
	{
		__m128i shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
		shuf = _mm_add_epi8(shuf, _mm_set1_epi8(16 - (pos >> 3)));
		shuf = _mm_and_si128(shuf, _mm_set1_epi8(0x0F));
		__m128i setmask = _mm_shuffle_epi8(_mm_cvtsi32_si128(1 << (pos & 0x7)), shuf);
		v = _mm_or_si128(v, setmask);
		//将位置为pos的位设置为1
	}
	//bool TestBitN(__m128i value, int N)
	//{
		//__m128i positioned = _mm_slli_epi64(value, 7 - (N & 7));
		//return (_mm_movemask_epi8(positioned) & (1 << (N / 8))) != 0;
		//判断第N位是否为1
	//}
	bool TestBitN(ECpoint& value, int N)
    {
        //确定 N 在哪个 128 位块中
        if (N < 128) {
            // 在前 16 字节中
            block blk = extractBlockFromECpoint(value, 0);
            __m128i positioned = _mm_slli_epi64(blk, 7 - (N & 7));
            return (_mm_movemask_epi8(positioned) & (1 << (N / 8))) != 0;
        } else {
            // 在后 16 字节中，调整 N
            N = N - 128;
            block blk = extractBlockFromECpoint(value, 1);
            __m128i positioned = _mm_slli_epi64(blk, 7 - (N & 7));
            return (_mm_movemask_epi8(positioned) & (1 << (N / 8))) != 0;
        }
    }

	BitPosition::BitPosition()
	{
	}

	BitPosition::~BitPosition()
	{
	}


	void BitPosition::print() const
	{
		std::cout << "mPos: \n";
		for (auto it = mPos.begin(); it != mPos.end(); ++it)
		{
			std::cout << static_cast<int16_t>(*it) << "  ";
		}
		std::cout << std::endl;
		std::cout << "Masks: ";
		for (auto iter = mMaps.begin(); iter != mMaps.end(); ++iter) {
			std::cout << static_cast<int16_t>((*iter)) << " ";
		}

	}
	void BitPosition::init(/*u64 numRealCodeWord,*/ u64 numMaxBitSize)
	{
		/*mRealBitSize= std::floor(std::log2(numRealCodeWord)) + 1;*/
		mMaxBitSize = numMaxBitSize;

	}

	//#################Table based
	//bool BitPosition::getMasks(std::vector<block>& codeword) {
	bool BitPosition::getMasks(std::vector<ECpoint>& codeword) {

		u8 rs, idx;
		for (size_t i = 0; i < codeword.size(); i++) {
			rs = 0;
			idx = 1;
			for (auto it = mPos.begin(); it != mPos.end(); ++it)
			{
				if (TestBitN(codeword[i], *it))
				{
					rs = rs^idx;
					//std::cout << static_cast<int16_t>(idx) << std::endl;
				}
				idx = idx << 1;
			}
			if (std::find(mMaps.begin(), mMaps.end(), rs) == mMaps.end())
			{
				mMaps.push_back(rs);
			}
			else
			{
				mMaps.clear();
				return false;
			}
		}
		return true;
	}
	//void BitPosition::getMask(block& codeword, u8& mask) {
	void BitPosition::getMask(ECpoint& codeword, u8& mask) {

		u8 /*rs,*/ idx;
		mask = 0;
		idx = 1;
		for (auto it = mPos.begin(); it != mPos.end(); ++it)
		{
			if (TestBitN(codeword, *it))
			{
				mask = mask^idx;
				//std::cout << static_cast<int16_t>(idx) << std::endl;
			}
			idx = idx << 1;
		}
	}

	//int BitPosition::midIdx(std::vector<block>& codewords, int length)
	int BitPosition::midIdx(std::vector<ECpoint>& codewords, int length)
	{
		size_t temp = 0;
		int idx = 0;
		size_t mid = 0;
		size_t cnt = 0;
		//std::cout << "temp ";
		if (codewords.size() == 1) {
			while (true)
			{
				auto rand = std::rand() % /*128*/length; //choose randome bit location
				if (std::find(mPos.begin(), mPos.end(), rand) == mPos.end())
				{
					return rand;
				}
			}
		}
		else if (codewords.size() == 2) {
			//block diff = codewords[0] ^ codewords[1];
			for (int j = 0; j < length; j++)
			{
				bool bit1 = TestBitN(codewords[0], j);
                bool bit2 = TestBitN(codewords[1], j);
				if (/*TestBitN(diff, j)*/bit1 != bit2)
					if (std::find(mPos.begin(), mPos.end(), j) == mPos.end())
					{
						return j;
					}
			}
		}
		else
			for (int j = 0; j < length; j++)
			{
				temp = 0;
				if (std::find(mPos.begin(), mPos.end(), j) == mPos.end())
				{
					cnt++;
					for (size_t i = 0; i < codewords.size(); i++)
					{
						if (TestBitN(codewords[i], j))
							temp++;
					}
					//std::cout << j << "," << temp << " ";
					if (temp < codewords.size() / 2 && mid < temp)
					{
						mid = temp;
						idx = j;
					}
				}
			}
		//	std::cout << idx << " - " << mid << " - " << codewords.size() << " - " << cnt << std::endl;
		return idx;
	}


	//std::vector<std::vector<block>> testSet;
	std::vector<std::vector<ECpoint>> testSet;
	int idxS = -1;
	//void BitPosition::getPosHelper(std::vector<block>& codewords, int length)
	void BitPosition::getPosHelper(std::vector<ECpoint>& codewords, int length)
	{
		idxS++;
		int setSize = codewords.size();
		//std::vector<block> testSet1;
		//std::vector<block> testSet2;
		std::vector<ECpoint> testSet1;
		std::vector<ECpoint> testSet2;

		if (mPos.size() < mRealBitSize) {
			int idx = midIdx(codewords, length);

			//if (std::find(mPos.begin(), mPos.end(), idx) == mPos.end())
			{
				mPos.push_back(idx);
				std::cout << std::endl;
				for (int i = 0; i < setSize; i++)
					if (TestBitN(codewords[i], idx))
					{
						//	std::cout << codewords[i] << " " << idx << " "<< 1 << std::endl;
						testSet1.push_back(codewords[i]);

					}
					else
					{
						//std::cout << codewords[i] << " " << idx << " " << 0 << std::endl;
						//std::cout << "TestBitN=0: " << i << std::endl;
						testSet2.push_back(codewords[i]);
					}

				//for (size_t i = 0; i < testSet1.size(); i++)
					//std::cout << testSet1[i] << " " << idx << " " << 1 << std::endl;

				//std::cout << std::endl;

				//for (size_t i = 0; i < testSet2.size(); i++)
					//std::cout << testSet2[i] << " " << idx << " " << 0 << std::endl;
					//输出testSet1和testSet2，这里省略


				testSet.push_back(testSet1);
				testSet.push_back(testSet2);
				//std::cout <<"testSet1 " <<  testSet1.size() << std::endl;
				//std::cout <<"testSet2 "<< testSet2.size() << std::endl;
				getPos(testSet[idxS], length);
			}
		}
	}

	//void BitPosition::getPos1(std::vector<block>& codewords, int length)
	void BitPosition::getPos1(std::vector<ECpoint>& codewords, int length)
	{
		bool isFind = false;

		if (codewords.size() == 1) {
			getRandPos();
			//std::cout << "getRandPos size=1" << std::endl;
			getMasks(codewords);
			//std::cout << "getMask size=1" << std::endl;
		}
		else if (codewords.size() == 2) {
			//block diff = codewords[0] ^ codewords[1];
			//while (!isFind)
			for (int j = 0; j < length && !isFind; j++) 
			{
				bool bit1 = TestBitN(codewords[0], j);
                bool bit2 = TestBitN(codewords[1], j);
				//u64 rand = std::rand() % length;
				if (/*TestBitN(diff, rand)*/bit1 != bit2)
				{
					mPos.push_back(j);
					isFind = true;
				}
			}
			getRandPos();
			getMasks(codewords);
		}
		else if (codewords.size() == 3) {
			//block diff = codewords[0] ^ codewords[1];
			//while (!isFind)
			for (int j = 0; j < length && !isFind; j++) 
			{
				//u64 rand = std::rand() % length;
				bool bit1 = TestBitN(codewords[0], j);
                bool bit2 = TestBitN(codewords[1], j);
				if (bit1 != bit2)
				{
					mPos.push_back(j);
					isFind = true;
				}
			} //find 1st position

			isFind = false; //start to find 2nd position
			//block diff2 = codewords[0] ^ codewords[2];

			//while (!isFind)
			for (int j = 0; j < length && !isFind; j++) 
			{
				bool bit1 = TestBitN(codewords[0], j);
				bool bit2 = TestBitN(codewords[2], j);
				bool bit3 = TestBitN(codewords[1], j);
				//u64 rand = std::rand() % length;
				//if (TestBitN(diff, rand) == false && TestBitN(diff2, rand) == true)
				if (bit1 != bit2 && bit1 == bit3)
				{
					if (std::find(mPos.begin(), mPos.end(), j) == mPos.end())
					{
						mPos.push_back(j);
						isFind = true;
					}
				}
			} //find 2nd position
			getRandPos();
			getMasks(codewords);
		}
		else
		{
			/*std::vector<block> diff;

			for (int i = 0; i + 1 < codewords.size(); i += 2) {
				diff.push_back(codewords[i] ^ codewords[i + 1]);
			}
			if (codewords.size() % 2 == 1)
				diff.push_back(codewords[codewords.size() - 1]);

			u64 sizeDiff = diff.size();

			while (!isFind)
			{
				mMaps.clear();
				mPos.clear();
				block m = ZeroBlock;
				while (mPos.size() < mMaxBitSize)
				{
					bool isRand = true;
					while (isRand)
					{
						u64 rIdx = std::rand() % length;
						u64 rDiffIdx = std::rand() % sizeDiff;
						if (TestBitN(diff[rDiffIdx], rIdx))
							if (std::find(mPos.begin(), mPos.end(), rIdx) == mPos.end())
							{
								mPos.push_back(rIdx);
								isRand = false;
								//setBit(m, rand);
							}
					}
				}
			*/
			while (!isFind)
            {
                mMaps.clear();
                mPos.clear();
                while (mPos.size() < mMaxBitSize)
                {
                    bool isRand = true;
                    while (isRand)
                    {
                        u64 rIdx = std::rand() % length;
                        u64 rCodewordIdx1 = std::rand() % codewords.size();
                        u64 rCodewordIdx2 = std::rand() % codewords.size();
                        if (rCodewordIdx1 != rCodewordIdx2) {
                            bool bit1 = TestBitN(codewords[rCodewordIdx1], rIdx);
                            bool bit2 = TestBitN(codewords[rCodewordIdx2], rIdx);
                            if (bit1 != bit2)
                                if (std::find(mPos.begin(), mPos.end(), rIdx) == mPos.end())
                                {
                                    mPos.push_back(rIdx);
                                    isRand = false;
                                }
                        }
                    }
                }

				//test mPos
				/*for (size_t i = 0; i < codewords.size(); i++)
				{
				block a = codewords[i] & m;
				Log::out << a << Log::endl;
				checkUnique.push_back(a);
				}*/

				isFind = getMasks(codewords);

				//// using default comparison:
				//std::vector<u8>::iterator it;
				//it = std::unique(mMaps.begin(), mMaps.end());

				////remove duplicate
				//mMaps.resize(std::distance(mMaps.begin(), it));

			}
		}
		//std::cout << "getPos completed" << codewords.size() << std::endl;
	}
	//void BitPosition::getPos(std::vector<block>& codewords, int length)
	void BitPosition::getPos(std::vector<ECpoint>& codewords, int length)
	{
		getPosHelper(codewords, length);
		//getRandPos();
	}
	void BitPosition::getRandPos()
	{
		while (mPos.size()<mMaxBitSize)
		{
			u64 rand = std::rand() % /*128*/256; //choose randome bit location
			if (std::find(mPos.begin(), mPos.end(), rand) == mPos.end())
			{
				mPos.push_back(rand);
			}
		}


	}
}