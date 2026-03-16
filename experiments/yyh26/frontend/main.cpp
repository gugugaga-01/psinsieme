
#include <iostream>
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

using namespace std;
#include "Common/Defines.h"
using namespace osuCrypto;

#include "OtBinMain.h"
#include "bitPosition.h"

#include <numeric>
#include "Common/Log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <time.h>

// #include "../libOLE/third_party/cryptoTools/cryptoTools/Common/Timer.h"
// #include "../libOLE/third_party/cryptoTools/cryptoTools/Common/Log.h"

// #include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Channel.h"
// #include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Session.h"
// #include "../libOLE/third_party/cryptoTools/cryptoTools/Network/IOService.h"

#include "../libOLE/src/lib/pke/ole.h"
#include "../libOLE/src/lib/pke/gazelle-network.h"
#include "../libOLE/src/lib/utils/debug.h"
// int miraclTestMain();

void usage(const char *argv0)
{
    std::cout << "Error! Please use:" << std::endl;
    std::cout << "\t 1. For unit test: " << argv0 << " -u" << std::endl;
    std::cout << "\t 2. For simulation (5 parties <=> 5 terminals): " << std::endl;
    ;
    std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;
}

int main(int argc, char **argv)
{
    u64 trials = 1;
    u64 nParties, threshold, setSize;
    bool useMultithread = false;

    // 基本参数校验（允许 9 或更多，因为可能带 -M）
    if (argc < 9)
    {
        usage(argv[0]);
        return 0;
    }

    if (argv[1][0] == '-' && argv[1][1] == 'n')
        nParties = atoi(argv[2]);
    else
    {
        usage(argv[0]);
        return 0;
    }
    if (argv[3][0] == '-' && argv[3][1] == 't')
        threshold = atoi(argv[4]);
    else
    {
        usage(argv[0]);
        return 0;
    }
    if (argv[5][0] == '-' && argv[5][1] == 'm')
        setSize = 1ull << atoi(argv[6]);
    else
    {
        usage(argv[0]);
        return 0;
    }

    u64 pIdx;
    if (argv[7][0] == '-' && argv[7][1] == 'p')
        pIdx = atoi(argv[8]);
    else
    {
        usage(argv[0]);
        return 0;
    }

    // 额外开关：扫描是否出现 -M（位置任意）
    for (int i = 9; i < argc; ++i)
    {
        if (argv[i][0] == '-' && argv[i][1] == 'M' && argv[i][2] == '\0')
        {
            useMultithread = true;
            break;
        }
    }

    // 运行
    if (useMultithread)
    {
        // std::cout << "run tparty_mt\n";
        tparty_mt(pIdx, nParties, threshold, setSize, trials);
    }
    else
    {
        // std::cout << "run tparty\n";
        tparty(pIdx, nParties, threshold, setSize, trials);
    }
    return 0;
}
// int main(int argc, char** argv)
// {

// 	u64 trials = 10;
// 	u64 pSetSize = 5, psiSecParam = 40, bitSize = 128;

// 	//u64 nParties, tParties, opt_basedOPPRF, setSize, isAug;
// 	u64 nParties, threshold, opt_basedOPPRF, setSize, isAug;
// 	u64 roundOPPRF;

// 	switch (argc) {
// 	case 9: //nPSI or optimized 3PSI
// 		//cout << "9\n";
// 		if (argv[1][0] == '-' && argv[1][1] == 'n')
// 			nParties = atoi(argv[2]);
// 		else
// 		{
// 			usage(argv[0]);
// 			return 0;
// 		}

// 		if (argv[3][0] == '-' && argv[3][1] == 't')
// 			threshold = atoi(argv[4]);
// 		else
// 		{
// 			usage(argv[0]);
// 			return 0;
// 		}

// 		if (argv[5][0] == '-' && argv[5][1] == 'm')
// 			setSize = 1 << atoi(argv[6]);
// 		else
// 		{
// 			usage(argv[0]);
// 			return 0;
// 		}

// 		if (argv[7][0] == '-' && argv[7][1] == 'p') {
// 			u64 pIdx = atoi(argv[8]);

// 		if (argv[3][1] == 't')
// 			{
// 				//cout << nParties << " " << tParties << " " << setSize << " " << pIdx << "\n";;
// 				tparty(pIdx, nParties, threshold, setSize, trials);
// 			}
// 		}
// 		else
// 		{
// 			usage(argv[0]);
// 			return 0;
// 		}
// 		break;
// 	}

// 	return 0;
// }
