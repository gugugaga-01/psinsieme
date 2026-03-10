// main.cpp

#include "../psi/OtMpsi.h"
#include "../psi/Logger.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Timer.h"
#include "coproto/Socket/AsioSocket.h"
#include "coproto/Socket/BufferingSocket.h"
#include "coproto/coproto.h"
#include <thread>
#include <mutex>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cmath>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <coroutine>

// Function to generate input sets with shared and unique items
std::vector<block> generateInputSet(
    u64 setSize,
    u64 sharedSize,
    u64 partyID,
    bool isLeader,
    OcPRNG &sharedPrng,
    OcPRNG &uniquePrng,
    Logger &logger)
{
    if (sharedSize > setSize)
    {
        throw std::invalid_argument("sharedSize cannot exceed setSize.");
    }

    std::vector<block> inputs(setSize);

    // Generate shared items
    for (u64 i = 0; i < sharedSize; ++i)
    {
        inputs[i] = sharedPrng.get<block>();
    }

    // Generate unique items
    for (u64 i = sharedSize; i < setSize; ++i)
    {
        inputs[i] = uniquePrng.get<block>();
    }

    logger.log((isLeader ? "Leader" : "Member"),
               " generated input set with ",
               sharedSize, " shared items and ",
               (setSize - sharedSize), " unique items.");

    return inputs;
}

// Function to initialize sockets based on role
std::vector<Socket> initializeLeaderSockets(u64 numMembers, Logger &logger)
{
    std::vector<Socket> sockets;
    sockets.reserve(numMembers);

    std::vector<std::thread> pThreads;
    {
        pThreads.clear();
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::string address = "0.0.0.0:" + std::to_string(30081 + memberIdx);
            // logger.log("Leader is waiting for member ", i, " to connect at ", address);
            try
            {
                sockets.emplace_back(coproto::asioConnect(address, true));
                // logger.log("Leader successfully connected to member ", i);
            }
            catch (const std::exception &e)
            {
                logger.error("Leader failed to connect to member ", memberIdx, " at ", address, ": ", e.what());
                throw; // Re-throw after logging
            }
        }

        for (auto &th : pThreads)
        {
            if (th.joinable())
                th.join();
        }
    }

    logger.log("Leader network setup done.");
    return sockets;
}

std::vector<coproto::Socket> initializeMemberSocket(u64 partyID, u64 numParties, Logger &logger)
{
    std::vector<coproto::Socket> sockets(3);

    std::string address = "127.0.0.1:" + std::to_string(30081 + partyID);
    // logger.log("Member ", partyID, " is connecting to leader at ", address);
    try
    {
        sockets[0] = coproto::asioConnect(address, false);
        // logger.log("Member ", partyID, " successfully connected to leader.");
    }
    catch (const std::exception &e)
    {
        logger.error("Member ", partyID, " failed to connect to leader at ", address, ": ", e.what());
        throw;
    }

    if (partyID != 0)
    {
        address = "0.0.0.0:" + std::to_string(30081 + numParties + partyID);
        // logger.log("Member ", partyID, " is  is waiting for member", partyID - 1, " at ", address);
        try
        {
            sockets[1] = coproto::asioConnect(address, true);
            // logger.log("Member ", partyID, " successfully connected to  member ", partyID - 1, ".");
        }
        catch (const std::exception &e)
        {
            logger.error("Member ", partyID, " failed to connect to member", partyID - 1, "at ", address, ": ", e.what());
            throw;
        }
    }

    if (partyID != numParties - 2)
    {
        address = "127.0.0.1:" + std::to_string(30081 + numParties + partyID + 1);
        // logger.log("Member ", partyID, " is connecting to member", partyID + 1, " at ", address);
        try
        {
            sockets[2] = coproto::asioConnect(address, false);
            // logger.log("Member ", partyID, " successfully connected to member", partyID + 1, ".");
        }
        catch (const std::exception &e)
        {
            logger.error("Member ", partyID, " failed to connect to member", partyID + 1, " at ", address, ": ", e.what());
            throw;
        }
    }
    logger.log("Member ", partyID, " network setup done.");

    return sockets;
}

bool socketIsValid(Socket &s)
{
    // 1) must actually have an implementation pointer
    if (!s.mImpl)
        return false;

    // 2) and it must not already have been closed()
    if (s.closed())
        return false;

    return true;
}

int main(int argc, char **argv)
{
    Logger &logger = Logger::getInstance();

    try
    {
        // Parse command-line arguments
        oc::CLP cmd;
        cmd.parse(argc, argv);

        u64 partyID = cmd.get<u64>("partyID");
        u64 numParties = cmd.get<u64>("numParties");
        u64 threshold = cmd.get<u64>("threshold");
        u64 senderSize = cmd.getOr("senderSize", 100);
        u64 receiverSize = cmd.getOr("receiverSize", 100);
        // u64 statSecParam = cmd.getOr("ssp", 40);
        u64 commonSeedVal = cmd.getOr<u64>("commonSeed", 0xDEADBEEFCAFEBABEULL);
        block commonSeed = oc::toBlock(commonSeedVal);
        bool debugFlag = cmd.isSet("debug");
        u64 sharedSize = cmd.getOr(
            "sharedSize",
            ((partyID == numParties - 1) ? receiverSize / 2 : senderSize / 2));
        // u64 inputBitSize = cmd.getOr("inputBitSize", 0); // Default input bit size
        // bool traceableFlag = cmd.isSet("traceable");
        // u64 bmType = cmd.getOr("binaryMapType", 0); // 0 for Bitmap

        // Number of runs for benchmarking
        u64 numRuns = cmd.getOr("numRuns", 1);

        // Determine role based on partyID and numParties
        bool isLeader = (partyID == numParties - 1);

        logger.setEnabled(debugFlag);

        if (partyID == numParties - 1)
        {

            namespace fs = std::filesystem;
            const fs::path keysDir = fs::path("keys");
            std::error_code ec;
            if (fs::exists(keysDir, ec))
                fs::remove_all(keysDir, ec);
            fs::create_directories(keysDir, ec);
            if (ec)
                throw std::runtime_error("[Leader] Failed to create " + keysDir.string());
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        // 1) threshold must be >1 and < numParties
        if (threshold <= 1 || threshold >= numParties)
        {
            throw std::invalid_argument(
                "threshold must be greater than 1 and less than numParties");
        }

        // Initialize PSI objects once
        OtMpPsiLeader leader;
        OtMpPsiMember member;
        OcPRNG sharedPrng(commonSeed);                            // PRNG for shared items
        OcPRNG uniquePrng(commonSeed ^ oc::toBlock(partyID + 1)); // PRNG for unique items
        if (isLeader)
        {
            leader.init(numParties, threshold, partyID, senderSize, receiverSize,
                        sharedPrng.get<block>(), debugFlag);
        }
        else
        {
            member.init(numParties, threshold, partyID, senderSize, receiverSize,
                        sharedPrng.get<block>(), debugFlag);
        }

        // Initialize sockets once
        std::vector<std::thread> thrds(numParties);
        std::vector<coproto::Socket> leaderSockets;
        std::vector<coproto::Socket> memberSockets;
        coproto::optional<boost::asio::io_context::work> w(coproto::global_io_context());
        if (isLeader)
        {
            for (auto &t : thrds)
            {
                t = std::thread([&]
                                { coproto::global_io_context().run(); });
            }
            leaderSockets = initializeLeaderSockets(numParties - 1, logger);
        }
        else
        {
            memberSockets = initializeMemberSocket(partyID, numParties, logger);
        }

        // Vector to store run times
        std::vector<double> runTimes;
        runTimes.reserve(numRuns);

        // Prepare Timer objects outside loop
        oc::Timer timer;
        if (isLeader)
        {
            leader.setTimer(timer);
        }
        else
        {
            member.setTimer(timer);
        }

        if (isLeader)
        {
            leader.setTimer(timer);
        }
        else
        {
            member.setTimer(timer);
        }

        if (isLeader)
        {
            leader.Sync(leaderSockets);
        }
        else
        {
            member.Sync(memberSockets);
        }

        if (isLeader)
        {
            logger.log("============================[ SETUP DONE ]============================");
        }

        // Perform multiple runs and measure times
        for (u64 runIdx = 0; runIdx < numRuns; ++runIdx)
        {
            // Regenerate inputs for each run
            std::vector<block> inputs;
            commonSeed = commonSeed ^ oc::toBlock(runIdx * 256);      // Increment seed for each run
            OcPRNG sharedPrng(commonSeed);                            // PRNG for shared items
            OcPRNG uniquePrng(commonSeed ^ oc::toBlock(partyID + 1)); // PRNG for unique items
            if (isLeader)
            {
                inputs = generateInputSet(receiverSize, sharedSize, partyID, true, sharedPrng, uniquePrng, logger);
            }
            else
            {
                inputs = generateInputSet(senderSize, sharedSize, partyID, false, sharedPrng, uniquePrng, logger);
            }

            if (isLeader)
            {
                leader.Sync(leaderSockets);
            }
            else
            {
                member.Sync(memberSockets);
            }

            timer.reset();
            auto start = timer.setTimePoint("start");

            if (isLeader)
            {
                logger.log("Leader is running the protocol (run ", runIdx + 1, " of ", numRuns, ")...");
                coproto::sync_wait(leader.Run(inputs, leaderSockets));
                logger.log("Leader completed run ", runIdx + 1);
            }
            else
            {
                logger.log("Member ", partyID, " is running the protocol (run ", runIdx + 1, " of ", numRuns, ")...");
                coproto::sync_wait(member.Run(inputs, memberSockets));
                logger.log("Member ", partyID, " completed run ", runIdx + 1);
            }

            auto end = timer.setTimePoint("end");
            double elapsedMs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
            double elapsedSec = elapsedMs / 1000.0;
            runTimes.push_back(elapsedSec);

            if (isLeader)
            {
                for (auto &socket : leaderSockets)
                {
                    if (socketIsValid(socket))
                    {
                        coproto::sync_wait(socket.flush());
                    }
                }
            }
            else
            {
                for (auto &socket : memberSockets)
                {
                    if (socketIsValid(socket))
                    {
                        coproto::sync_wait(socket.flush());
                    }
                }
            }
        }

        // Close sockets after all runs are done
        if (isLeader)
        {
            w.reset();

            for (auto &socket : leaderSockets)
            {
                if (socketIsValid(socket))
                {
                    coproto::sync_wait(socket.flush());
                    coproto::sync_wait(socket.close());
                }
            }

            coproto::global_io_context().stop();

            for (auto &t : thrds)
                t.join();
        }
        else
        {
            for (auto &socket : memberSockets)
            {
                if (socketIsValid(socket))
                {
                    coproto::sync_wait(socket.flush());
                    coproto::sync_wait(socket.close());
                }
            }
        }

        // If debugging, print all run times
        if (debugFlag)
        {
            std::cout << "Run times: ";
            for (auto t : runTimes)
            {
                std::cout << t << "s ";
            }
            std::cout << std::endl;
        }

        // After all runs and after closing sockets:
        {
            // Compute average and stddev
            double sum = 0.0;
            for (auto t : runTimes)
                sum += t;
            double average = sum / runTimes.size();

            double variance = 0.0;
            if (runTimes.size() > 1)
            {
                for (auto t : runTimes)
                {
                    double diff = t - average;
                    variance += diff * diff;
                }
                variance /= (runTimes.size() - 1);
            }
            double stddev = std::sqrt(variance);

            // Compute total sent/received bytes
            u64 totalSentBytes = 0;
            u64 totalRecvBytes = 0;
            // if (isLeader)
            // {
            //     for (auto &chl : leaderSockets)
            //     {
            //         totalSentBytes += chl.bytesSent();
            //         totalRecvBytes += chl.bytesReceived();
            //     }
            // }
            // else if (partyID == 1)
            // {
            //     for (auto &chl : memberSockets)
            //     {
            //         totalSentBytes += chl.bytesSent();
            //         totalRecvBytes += chl.bytesReceived();
            //     }
            // }

            if (isLeader)
            {
                // Leader：统计所有 leaderSockets
                for (auto &chl : leaderSockets)
                {                 
                    totalSentBytes += chl.bytesSent();
                    totalRecvBytes += chl.bytesReceived();
                }
            }
            else if (partyID == 0)
            {
                // 边界 Member：party 0
                // 当前拓扑下，0 号只会用到 sockets[0]（连 leader）和 sockets[2]（连 1 号）
                if (memberSockets.size() > 0)
                {
                    totalSentBytes += memberSockets[0].bytesSent();
                    totalRecvBytes += memberSockets[0].bytesReceived();
                }
                if (memberSockets.size() > 2)
                {
                    totalSentBytes += memberSockets[2].bytesSent();
                    totalRecvBytes += memberSockets[2].bytesReceived();
                }
            }
            else if (partyID == numParties - 2)
            {
                // 边界 Member：最后一个 Member（numParties-2）
                // 只会用到 sockets[0]（连 leader）和 sockets[1]（连前一个 Member）
                if (memberSockets.size() > 0)
                {
                    totalSentBytes += memberSockets[0].bytesSent();
                    totalRecvBytes += memberSockets[0].bytesReceived();
                }
                if (memberSockets.size() > 1)
                {
                    totalSentBytes += memberSockets[1].bytesSent();
                    totalRecvBytes += memberSockets[1].bytesReceived();
                }
            }
            else
            {
                // 中间的 Member：0,1,2 三个 socket 都是有效连接
                for (auto &chl : memberSockets)   
                {
                   
                    totalSentBytes += chl.bytesSent();
                    totalRecvBytes += chl.bytesReceived();
                }
            }


            // Convert bytes to MB
            double sentMB = static_cast<double>(totalSentBytes) / (1024.0 * 1024.0) / numRuns;
            double recvMB = static_cast<double>(totalRecvBytes) / (1024.0 * 1024.0) / numRuns;

            // Build output in a single string
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(3); // 3 decimal places

            // if (isLeader)
            // {
            //     // Leader prints full benchmark info
            //     oss << "************************************************************\n";
            //     oss << "Benchmark Info:\n";
            //     oss << "------------------------------------------------------------\n"
            //         << std::setw(18) << std::left << "Number of Parties:" << numParties << "\n"
            //         << std::setw(18) << std::left << "Sender Size:" << senderSize << "\n"
            //         << std::setw(18) << std::left << "Receiver Size:" << receiverSize << "\n"
            //         << std::setw(18) << std::left << "Number of Runs:" << numRuns << "\n";
            //     oss << "Timing Results:\n";
            //     oss << "------------------------------------------------------------\n"
            //         << std::setw(18) << std::left << "Average time:" << average << " s\n"
            //         << std::setw(18) << std::left << "StdDev:" << stddev << " s\n\n";

            //     oss << "Network Costs:\n";
            //     oss << "------------------------------------------------------------\n"
            //         << std::setw(18) << std::left << "Sent:" << sentMB << " MB\n"
            //         << std::setw(18) << std::left << "Received:" << recvMB << " MB\n\n";

            //     oss << "Role:\n";
            //     oss << "------------------------------------------------------------\n"
            //         << "[Leader] completed " << numRuns << " runs.\n";
            // }
            // else if (partyID == 1)
            // {
            //     // Only Member 0 prints communication summary
            //     oss << "************************************************************\n";
            //     oss << "Communication Costs [Member]:\n";
            //     oss << "------------------------------------------------------------\n"
            //         << std::setw(18) << std::left << "Sent:" << sentMB << " MB\n"
            //         << std::setw(18) << std::left << "Received:" << recvMB << " MB\n\n"
            //         << "[Member] completed " << numRuns << " runs.\n";
            // }
            if (isLeader)
            {
                // Leader prints full benchmark info
                oss << "************************************************************\n";
                oss << "Benchmark Info:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Number of Parties:" << numParties << "\n"
                    << std::setw(18) << std::left << "Sender Size:" << senderSize << "\n"
                    << std::setw(18) << std::left << "Receiver Size:" << receiverSize << "\n"
                    << std::setw(18) << std::left << "Number of Runs:" << numRuns << "\n";
                oss << "Timing Results:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Average time:" << average << " s\n"
                    << std::setw(18) << std::left << "StdDev:" << stddev << " s\n\n";

                oss << "Network Costs:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Sent:" << sentMB << " MB\n"
                    << std::setw(18) << std::left << "Received:" << recvMB << " MB\n\n";

                oss << "Role:\n";
                oss << "------------------------------------------------------------\n"
                    << "[Leader] completed " << numRuns << " runs.\n";
            }
            else
            {
                oss << "************************************************************\n";
                oss << "Communication Costs [Member"<< partyID <<"]:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Sent:" << sentMB << " MB\n"
                    << std::setw(18) << std::left << "Received:" << recvMB << " MB\n\n"
                    << "[Member] completed " << numRuns << " runs.\n";
            }

            // Print the result
            // if (isLeader || partyID == 1)
            // {
            //     std::cout << oss.str();
            //     std::cout.flush();
            // }
            std::cout << oss.str();
            std::cout.flush();
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
