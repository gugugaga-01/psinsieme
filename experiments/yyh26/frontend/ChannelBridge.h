#pragma once
// Bridge between OPPRF's osuCrypto::Channel (old API) and
// libOLE's osuCryptoNew::Channel (new API).
//
// Uses libOLE's SocketAdapter pattern: wraps an osuCrypto::Channel
// so it can be used as an osuCryptoNew::Channel.

#include "Network/Channel.h"                // OPPRF Channel (osuCrypto)

#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/Channel.h"     // OLE Channel (osuCryptoNew)
#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/IOService.h"   // OLE IOService
#include "../libOLE/third_party/cryptoTools/cryptoTools/Network/SocketAdapter.h"

namespace yyh26 {

// Custom SocketInterface that delegates to osuCrypto::Channel (OPPRF).
// Unlike the generic SocketAdapter<T>, this handles the missing asyncCancel.
class OPPRFSocketAdapter : public osuCryptoNew::SocketInterface
{
public:
    osuCrypto::Channel& mChl;
    osuCryptoNew::IOService* mIos = nullptr;

    OPPRFSocketAdapter(osuCrypto::Channel& chl) : mChl(chl) {}
    ~OPPRFSocketAdapter() override {}

    void setIOService(osuCryptoNew::IOService& ios) override { mIos = &ios; }

    void async_send(
        osuCryptoNew::span<boost::asio::mutable_buffer> buffers,
        osuCryptoNew::io_completion_handle&& fn) override
    {
        osuCryptoNew::post(mIos, [this, buffers, fn]() {
            boost::system::error_code ec;
            osuCryptoNew::u64 bytesTransfered = 0;
            for (osuCryptoNew::u64 i = 0; i < osuCryptoNew::u64(buffers.size()); ++i) {
                try {
                    auto data = boost::asio::buffer_cast<osuCryptoNew::u8*>(buffers[i]);
                    auto size = boost::asio::buffer_size(buffers[i]);
                    mChl.send(data, size);
                    bytesTransfered += size;
                } catch (...) {
                    ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                    break;
                }
            }
            fn(ec, bytesTransfered);
        });
    }

    void async_recv(
        osuCryptoNew::span<boost::asio::mutable_buffer> buffers,
        osuCryptoNew::io_completion_handle&& fn) override
    {
        osuCryptoNew::post(mIos, [this, buffers, fn]() {
            boost::system::error_code ec;
            osuCryptoNew::u64 bytesTransfered = 0;
            for (osuCryptoNew::u64 i = 0; i < osuCryptoNew::u64(buffers.size()); ++i) {
                try {
                    auto data = boost::asio::buffer_cast<osuCryptoNew::u8*>(buffers[i]);
                    auto size = boost::asio::buffer_size(buffers[i]);
                    mChl.recv(data, size);
                    bytesTransfered += size;
                } catch (...) {
                    ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                    break;
                }
            }
            fn(ec, bytesTransfered);
        });
    }

    void cancel() override {
        // OPPRF Channel doesn't support asyncCancel; no-op.
    }
};

// Create an osuCryptoNew::Channel that wraps an osuCrypto::Channel.
// The returned channel uses the OPPRF channel's underlying TCP connection.
// The IOService must outlive the returned channel.
inline osuCryptoNew::Channel bridgeChannel(
    osuCryptoNew::IOService& ios,
    osuCrypto::Channel& opprfChl)
{
    auto* adapter = new OPPRFSocketAdapter(opprfChl);
    return osuCryptoNew::Channel(ios, adapter);
}

} // namespace yyh26
