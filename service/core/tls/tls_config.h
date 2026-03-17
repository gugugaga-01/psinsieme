#pragma once

#include <grpcpp/grpcpp.h>
#include <fstream>
#include <memory>
#include <string>

namespace mpsi {

// Configuration for TLS/mTLS
struct TlsConfig {
    std::string server_cert;
    std::string server_key;
    std::string ca_cert;
    bool enable_mtls = false;
};

inline std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    return std::string(std::istreambuf_iterator<char>(file),
                       std::istreambuf_iterator<char>());
}

inline std::shared_ptr<grpc::ServerCredentials> makeServerCredentials(const TlsConfig& tls) {
    if (tls.server_cert.empty())
        return grpc::InsecureServerCredentials();

    grpc::SslServerCredentialsOptions opts;
    opts.pem_root_certs = tls.ca_cert;
    opts.pem_key_cert_pairs.push_back({tls.server_key, tls.server_cert});
    if (tls.enable_mtls)
        opts.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
    return grpc::SslServerCredentials(opts);
}

inline std::shared_ptr<grpc::ChannelCredentials> makeClientCredentials(const TlsConfig& tls) {
    if (tls.server_cert.empty())
        return grpc::InsecureChannelCredentials();

    grpc::SslCredentialsOptions opts;
    opts.pem_root_certs = tls.ca_cert;
    if (tls.enable_mtls) {
        opts.pem_private_key = tls.server_key;
        opts.pem_cert_chain = tls.server_cert;
    }
    return grpc::SslCredentials(opts);
}

} // namespace mpsi
