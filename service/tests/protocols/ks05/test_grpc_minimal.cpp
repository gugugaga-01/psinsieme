#include <iostream>
#include <thread>
#include <chrono>

#include <grpcpp/grpcpp.h>
#include "ks05_party.grpc.pb.h"

class EchoService final : public mpsi::ks05::Ks05PartyService::Service {
public:
    grpc::Status ProtocolChannel(
        grpc::ServerContext* /*context*/,
        grpc::ServerReaderWriter<mpsi::ks05::ChannelMessage, mpsi::ks05::ChannelMessage>* stream) override {

        std::cout << "[Server] ProtocolChannel handler called!" << std::endl;

        mpsi::ks05::ChannelMessage msg;
        while (stream->Read(&msg)) {
            std::cout << "[Server] Received value: " << msg.value() << std::endl;
            mpsi::ks05::ChannelMessage reply;
            reply.set_value(msg.value() * 2);
            stream->Write(reply);
        }

        std::cout << "[Server] Stream ended" << std::endl;
        return grpc::Status::OK;
    }
};

int main() {
    std::cout << "=== Minimal gRPC Bidi Stream Test ===" << std::endl;

    // Disable proxy for gRPC
    setenv("no_proxy", "127.0.0.1,localhost", 1);
    setenv("NO_PROXY", "127.0.0.1,localhost", 1);

    EchoService service;

    grpc::ServerBuilder builder;
    int selected_port = 0;
    builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &selected_port);
    builder.RegisterService(&service);
    auto server = builder.BuildAndStart();

    if (!server) {
        std::cerr << "Failed to start server!" << std::endl;
        return 1;
    }

    std::cout << "[Server] Listening on port " << selected_port << std::endl;

    // Client
    std::string target = "127.0.0.1:" + std::to_string(selected_port);

    grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);
    auto channel = grpc::CreateCustomChannel(target, grpc::InsecureChannelCredentials(), args);

    std::cout << "[Client] Connecting to " << target << std::endl;
    bool ok = channel->WaitForConnected(
        std::chrono::system_clock::now() + std::chrono::seconds(5));
    std::cout << "[Client] Connected: " << ok << std::endl;

    auto stub = mpsi::ks05::Ks05PartyService::NewStub(channel);
    grpc::ClientContext ctx;
    auto stream = stub->ProtocolChannel(&ctx);

    mpsi::ks05::ChannelMessage msg;
    msg.set_value(42);
    stream->Write(msg);
    std::cout << "[Client] Sent 42" << std::endl;

    mpsi::ks05::ChannelMessage reply;
    bool read_ok = stream->Read(&reply);
    std::cout << "[Client] Read ok: " << read_ok << " value: " << reply.value() << std::endl;

    stream->WritesDone();
    auto status = stream->Finish();
    std::cout << "[Client] Status: " << status.error_code() << " " << status.error_message() << std::endl;

    server->Shutdown();

    if (read_ok && reply.value() == 84) {
        std::cout << "\nTEST PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << "\nTEST FAILED" << std::endl;
        return 1;
    }
}
