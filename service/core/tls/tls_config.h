#pragma once

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_certificate_verifier.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <fstream>
#include <memory>
#include <string>

namespace mpsi {

enum class TlsMode { INSECURE, TLS, MTLS };

struct TlsConfig {
    std::string server_cert;
    std::string server_key;
    std::string ca_cert;
    TlsMode mode = TlsMode::INSECURE;
};

inline std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    return std::string(std::istreambuf_iterator<char>(file),
                       std::istreambuf_iterator<char>());
}

inline std::shared_ptr<grpc::ServerCredentials> makeServerCredentials(const TlsConfig& tls) {
    if (tls.mode == TlsMode::INSECURE || tls.server_cert.empty())
        return grpc::InsecureServerCredentials();

    grpc::SslServerCredentialsOptions opts;
    opts.pem_root_certs = tls.ca_cert;
    opts.pem_key_cert_pairs.push_back({tls.server_key, tls.server_cert});
    if (tls.mode == TlsMode::MTLS)
        opts.client_certificate_request = GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
    return grpc::SslServerCredentials(opts);
}

inline std::shared_ptr<grpc::ChannelCredentials> makeClientCredentials(const TlsConfig& tls) {
    if (tls.mode == TlsMode::INSECURE || tls.server_cert.empty())
        return grpc::InsecureChannelCredentials();

    if (tls.mode == TlsMode::TLS) {
        // Encrypt-only: use NoOpCertificateVerifier so we don't need to
        // distribute a shared CA.  The channel is encrypted but neither
        // side's identity is verified.
        auto opts = std::make_shared<grpc::experimental::TlsChannelCredentialsOptions>();
        opts->set_certificate_verifier(
            std::make_shared<grpc::experimental::NoOpCertificateVerifier>());
        opts->set_verify_server_certs(false);
        return grpc::experimental::TlsCredentials(*opts);
    }

    // MTLS: full verification with client cert
    grpc::SslCredentialsOptions opts;
    opts.pem_root_certs = tls.ca_cert;
    opts.pem_private_key = tls.server_key;
    opts.pem_cert_chain = tls.server_cert;
    return grpc::SslCredentials(opts);
}

} // namespace mpsi
