/**
 * @file test-network  --  tests network functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <time.h>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "pke/bfv.h"
#include "pke/gazelle-network.h"
#include "utils/debug.h"

using namespace lbcrypto;
using namespace osuCryptoNew;

const std::string addr = "localhost";
// const std::string addr = "18.204.1.19";
// const std::string addr = "172.31.59.125";
const uint32_t port = 9090;

const ui32 nRep = 10;

void server() {

    //
    // Networking Setup
    //
    std::cout << "Server\n";
    IOService ios(8);
    std::cout << " Server Created IO service\n";
    Session sess(ios, addr, port, EpMode::Server);
    std::cout << "Server created session\n";
    Channel chl = sess.addChannel();
    std::cout << "Server created channel\n";

    for (ui32 rep = 0; rep < nRep; rep++) {
        int val;
        chl.recv(val);
        // assert(val==1);
        chl.send(1);
    }

    // 8 bytes, 128 is a KB, 131072 is a MB, *1024 is a GB 
    std::vector<ui64> toSend(131072*1024);
    double start = currentDateTime();
    for (ui32 rep = 0; rep < nRep; rep++) {
        chl.recv(toSend);
        chl.send(toSend);
    }
    double end = currentDateTime();
    std::cout << "RTT = " << (end-start)/nRep << " ms" << std::endl;
    std::cout << "latency = " << (end-start)/nRep/2 << " ms" << std::endl;

    for (ui32 i = 0; i < toSend.size(); i++)
        assert(toSend[i] == i);

    chl.close();
    sess.stop();
    ios.stop();
	return;
}

void client() {

    //
    // Networking Setup
    //
    std::cout << "Client\n";
    IOService ios(1);
    std::cout << "Client created IO service\n";
    Session sess(ios, addr, port, EpMode::Client);
    std::cout << "Client created session\n";
    Channel chl = sess.addChannel();
    std::cout << "Client created channels\n";

    chl.waitForConnection();

    double start = currentDateTime();
    for (ui32 rep = 0; rep < nRep; rep++) {
        chl.send(1);
        int val; chl.recv(val);
    }
    double end = currentDateTime();
    std::cout << "RTT = " << (end-start)/nRep << " ms" << std::endl;


    // 8 bytes, 128 is a KB, 131072 is a MB, *1024 is a GB 
    std::vector<ui64> toSend(131072*1024);
    for (ui32 i = 0; i < toSend.size(); i++)
        toSend[i] = i;
    start = currentDateTime();
    for (ui32 rep = 0; rep < nRep; rep++) {
        chl.send(toSend);
        chl.recv(toSend);
    }
    end = currentDateTime();
    std::cout << "RTT = " << (end-start)/nRep << " ms" << std::endl;
    std::cout << "latency = " << (end-start)/nRep/2 << " ms" << std::endl;

    

    chl.close();
    sess.stop();
    ios.stop();
	return;
}

int main(int argc, char** argv) {

	if (argc == 1) {
		std::vector<std::thread> thrds(2);
		thrds[0] = std::thread([]() { client(); });
		thrds[1] = std::thread([]() { server(); });

        for (auto& thrd : thrds)
            thrd.join();
	}
	else if(argc == 2) {
		int role = atoi(argv[1]); // 0: send, 1: recv
		role ? server() : client();
	}
    else {
      std::cout << "this program takes a runtime argument.\n\n"
        << "to run the AES GC, run\n\n"
        << "    demo-relu [0|1]\n\n"
        << "the optional {0,1} argument specifies in which case the program will\n"
        << "run between two terminals, where each one was set to the opposite value. e.g.\n\n"
        << "    demo-relu 0\n\n"
        << "    demo-relu 1\n\n"
        << "These programs are fully networked and try to connect at localhost:1212.\n"
        << std::endl;
    }
}
