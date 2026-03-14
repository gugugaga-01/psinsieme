/**
 * @file gazelle-network.h  --  Provides an API for sending and receiving objects using cryptoTools channels.
 */

#ifndef LBCRYPTO_GAZELLE_NETWORK_H
#define LBCRYPTO_GAZELLE_NETWORK_H

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include <iostream>
#include <fstream>
#include <iterator>

#include "bfv.h"

// #include "stringbuffer.h"
// #include "writer.h"

using namespace osuCryptoNew;

namespace lbcrypto {
    using Channel = osuCryptoNew::Channel;

    /** Ciphertexts **/

    // WARNING: will block until the other party calls receiveCiphertext
    template<typename DCRTPoly>
    void sendCiphertext(const DCRT_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        constexpr ui32 phim = DCRT_Ciphertext<DCRTPoly>::phim;
        constexpr ui32 numLimbs = DCRT_Ciphertext<DCRTPoly>::numLimbs;
        for (ui32 i = 0; i < numLimbs; i++) {
            chl.send(ct.a.vals[i], phim);
            chl.send(ct.b.vals[i], phim);
        }
    }

    // WARNING: Must ensure input ct life extends until data is sent
    template<typename DCRTPoly>
    void asyncSendCiphertext(const DCRT_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        const ui32 phim = DCRT_Ciphertext<DCRTPoly>::phim;
        const ui32 numLimbs = DCRT_Ciphertext<DCRTPoly>::numLimbs;
        for (ui32 i = 0; i < numLimbs; i++) {
            chl.asyncSend(ct.a.vals[i], phim);
            chl.asyncSend(ct.b.vals[i], phim);
        }
    }


    // WARNING: will block until the other party calls sendCiphertext
    template<typename DCRTPoly>
    void receiveCiphertext(DCRT_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        constexpr ui32 phim = DCRT_Ciphertext<DCRTPoly>::phim;
        constexpr ui32 numLimbs = DCRT_Ciphertext<DCRTPoly>::numLimbs;
        // ct.a.zeros(); ct.b.zeros();
        for (ui32 i = 0; i < numLimbs; i++) {
            chl.recv(ct.a.vals[i], phim);
            chl.recv(ct.b.vals[i], phim);
        }
    }

    // WARNING: will block until the other party calls receiveCiphertext
    template<typename poly>
    void sendCiphertext(const Single_Limb_Ciphertext<poly>& ct, Channel& chl) {
        constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
        chl.send(ct.a.vals, phim);
        chl.send(ct.b.vals, phim);
    }

    template<typename poly>
    void asyncSendCiphertextCopy(const Single_Limb_Ciphertext<poly>& ct, Channel& chl) {
        constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
        chl.asyncSendCopy(ct.a.vals, phim);
        chl.asyncSendCopy(ct.b.vals, phim);
    }

    // WARNING: Must ensure input ct life extends until data is sent
    template<typename poly>
    void asyncSendCiphertext(const Single_Limb_Ciphertext<poly>& ct, Channel& chl) {
        constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
        chl.asyncSend(ct.a.vals, phim);
        chl.asyncSend(ct.b.vals, phim);
    }

    // WARNING: will block until the other party calls sendCiphertext
    template<typename poly>
    void receiveCiphertext(Single_Limb_Ciphertext<poly>& ct, Channel& chl) {
        constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
        ct.a.zeros(); ct.b.zeros();
        chl.recv(ct.a.vals, phim);
        chl.recv(ct.b.vals, phim);
    }


    // WARNING: will block until the other party calls receiveCiphertext
    template<typename DCRTPoly>
    void sendCiphertext(const DCRT_Seeded_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
        chl.send(ct.seed);
        for (ui32 i = 0; i < numLimbs; i++)
            chl.send(ct.b.vals[i], phim);
    }

    template<typename DCRTPoly>
    void asyncSendCiphertextCopy(const DCRT_Seeded_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
        chl.asyncSendCopy(ct.seed);
        for (ui32 i = 0; i < numLimbs; i++)
            chl.asyncSendCopy(ct.b.vals[i], phim);
    }

    // WARNING: Must ensure input ct life extends until data is sent
    template<typename DCRTPoly>
    void asyncSendCiphertext(const DCRT_Seeded_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
        chl.asyncSend(ct.seed);
        for (ui32 i = 0; i < numLimbs; i++)
            chl.asyncSend(ct.b.vals[i], phim);
    }


    // WARNING: will block until the other party calls sendCiphertext
    template<typename DCRTPoly>
    void receiveCiphertext(DCRT_Seeded_Ciphertext<DCRTPoly>& ct, Channel& chl) {
        constexpr ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        constexpr ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
        // ct.b.zeros();
        chl.recv(ct.seed);
        for (ui32 i = 0; i < numLimbs; i++)
            chl.recv(ct.b.vals[i], phim);
    }


    template<typename CiphertextType>
    void sendCiphertextVector(const std::vector<CiphertextType>& toSend, Channel& chl) {
        chl.send(toSend.size());
        for (ui32 i = 0; i < toSend.size(); i++)
            sendCiphertext(toSend[i], chl);
    }

    template<typename CiphertextType>
    void receiveCiphertextVector(std::vector<CiphertextType>& toLoad, Channel& chl, const bool verbose = false) {
        size_t h; chl.recv(h);
        if (verbose) 
            std::cout << "Receiving ciphertext vector of size " << h << std::endl;
        toLoad = std::vector<CiphertextType>(h);
        for (ui32 i = 0; i < h; i++)
            receiveCiphertext(toLoad[i], chl);
    }


    template<typename CiphertextType>
    void sendCiphertextMatrix(const std::vector<std::vector<CiphertextType>>& toSend, Channel& chl) {
        chl.send(toSend.size());
        chl.send(toSend[0].size());
        for (ui32 i = 0; i < toSend.size(); i++)
            for (ui32 j = 0; j < toSend[0].size(); j++)
                sendCiphertext(toSend[i][j], chl);
    }

    template<typename CiphertextType>
    void receiveCiphertextMatrix(std::vector<std::vector<CiphertextType>>& toLoad, Channel& chl) {
        size_t h; chl.recv(h);
        size_t w; chl.recv(w);
        toLoad = std::vector<std::vector<CiphertextType>>(h, std::vector<CiphertextType>(w));
        for (ui32 i = 0; i < h; i++)
            for (ui32 j = 0; j < w; j++)
                receiveCiphertext(toLoad[i][j], chl);
    }

    // template<typename CiphertextType>
    // void sendCiphertext4dData(const std::vector<std::vector<std::vector<CiphertextType>>>& toSend, Channel& chl) {
    //     chl.send(toSend.size());
    //     chl.send(toSend[0].size());
    //     chl.send(toSend[0][0].size());
    //     for (ui32 i = 0; i < toSend.size(); i++)
    //         for (ui32 j = 0; j < toSend[0].size(); j++)
    //             for (ui32 k = 0; k < toSend[0][0].size(); k++)
    //                 sendCiphertext(toSend[i][j][k], chl);
    // }

    // template<typename CiphertextType>
    // void receiveCiphertext4dData(std::vector<std::vector<std::vector<CiphertextType>>>& toLoad, Channel& chl) {
    //     size_t h; chl.recv(h);
    //     size_t w; chl.recv(w);
    //     size_t d; chl.recv(d);
    //     toLoad = std::vector<std::vector<std::vector<CiphertextType>>>(h, 
    //         std::vector<std::vector<CiphertextType>>(w, std::vector<CiphertextType>(d)));
    //     for (ui32 i = 0; i < h; i++)
    //         for (ui32 j = 0; j < w; j++)
    //             for (ui32 k = 0; k < d; k++)
    //                 receiveCiphertext(toLoad[i][j][k], chl);
    // }


    /** DCRT Poly **/

    // WARNING: will block until the other party calls receiveCiphertext
    template<typename DCRTPoly>
    void sendDCRTPoly(const DCRTPoly& input, Channel& chl) {
        constexpr ui32 phim = DCRTPoly::phim;
        constexpr ui32 numLimbs = DCRTPoly::numLimbs;
        for (ui32 i = 0; i < numLimbs; i++)
            chl.send(input.vals[i], phim);
    }


    // WARNING: will block until the other party calls sendCiphertext
    template<typename DCRTPoly>
    void receiveDCRTPoly(const DCRTPoly& input, Channel& chl) {
        constexpr ui32 phim = DCRTPoly::phim;
        constexpr ui32 numLimbs = DCRTPoly::numLimbs;
        for (ui32 i = 0; i < numLimbs; i++)
            chl.recv(input.vals[i], phim);
    }

    // // WARNING: will block until the other party calls receiveCiphertext
    // template<typename DCRTPoly>
    // void asyncSendDCRTPoly(const DCRTPoly& input, Channel& chl) {
    //     constexpr ui32 phim = DCRTPoly::phim;
    //     constexpr ui32 numLimbs = DCRTPoly::numLimbs;
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.asyncsend(input.vals[i], phim);
    // }


    // // WARNING: will block until the other party calls sendCiphertext
    // template<typename DCRTPoly>
    // void asyncReceiveDCRTPoly(const DCRTPoly& input, Channel& chl) {
    //     constexpr ui32 phim = DCRTPoly::phim;
    //     constexpr ui32 numLimbs = DCRTPoly::numLimbs;
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.asyncrecv(input.vals[i], phim);
    // }

    template<typename PolyType>
    void sendDCRTPolyVector(const std::vector<PolyType>& toSend, Channel& chl) {
        chl.send(toSend.size());
        for (ui32 i = 0; i < toSend.size(); i++)
            sendDCRTPoly(toSend[i], chl);
    }

    template<typename PolyType>
    void receiveDCRTPolyVector(std::vector<PolyType>& toLoad, Channel& chl) {
        size_t h; chl.recv(h);
        toLoad = std::vector<PolyType>(h);
        for (ui32 i = 0; i < h; i++)
            receiveDCRTPoly(toLoad[i], chl);
    }

    // template<typename PolyType>
    // void asyncSendDCRTPolyVector(const std::vector<PolyType>& toSend, Channel& chl) {
    //     chl.asyncSend(toSend.size());
    //     for (ui32 i = 0; i < toSend.size(); i++)
    //         asyncSendDCRTPoly(toSend[i], chl);
    // }

    // template<typename PolyType>
    // void asyncreceiveDCRTPolyVector(std::vector<PolyType>& toLoad, Channel& chl) {
    //     size_t h; chl.asyncRecv(h);
    //     toLoad = std::vector<PolyType>(h);
    //     for (ui32 i = 0; i < h; i++)
    //         asyncReceiveDCRTPoly(toLoad[i], chl);
    // }

    template<typename PolyType>
    void sendDCRTPolyMatrix(const std::vector<std::vector<PolyType>>& toSend, Channel& chl) {
        chl.send(toSend.size());
        chl.send(toSend[0].size());
        for (ui32 i = 0; i < toSend.size(); i++)
            for (ui32 j = 0; j < toSend[0].size(); j++)
                sendDCRTPoly(toSend[i][j], chl);
    }

    template<typename PolyType>
    void receiveDCRTPolyMatrix(std::vector<std::vector<PolyType>>& toLoad, Channel& chl) {
        size_t h; chl.recv(h);
        size_t w; chl.recv(w);
        toLoad = std::vector<std::vector<PolyType>>(h, std::vector<PolyType>(w));
        for (ui32 i = 0; i < h; i++)
            for (ui32 j = 0; j < w; j++)
                receiveDCRTPoly(toLoad[i][j], chl);
    }

    template<typename PolyType>
    void sendDCRTPolyFilter(const std::vector<std::vector<std::vector<PolyType>>>& toSend, Channel& chl) {
        chl.send(toSend.size());
        chl.send(toSend[0].size());
        chl.send(toSend[0][0].size());
        for (ui32 i = 0; i < toSend.size(); i++)
            for (ui32 j = 0; j < toSend[0].size(); j++)
                for (ui32 k = 0; k < toSend[0][0].size(); k++)
                    sendDCRTPoly(toSend[i][j][k], chl);
    }

    template<typename PolyType>
    void receiveDCRTPolyFilter(std::vector<std::vector<std::vector<PolyType>>>& toLoad, Channel& chl) {
        size_t h; chl.recv(h);
        size_t w; chl.recv(w);
        size_t d; chl.recv(d);
        toLoad =
            std::vector<std::vector<std::vector<PolyType>>>(
                h, std::vector<std::vector<PolyType>>(
                    w, std::vector<PolyType>(d)
                )
            );
        for (ui32 i = 0; i < h; i++)
            for (ui32 j = 0; j < w; j++)
                for (ui32 k = 0; k < d; k++)
                    receiveDCRTPoly(toLoad[i][j][k], chl);
    }

    /** Keys **/

    template <typename DCRTPoly>
    void sendPublicKey(const PublicKeyDCRT<DCRTPoly>& pk, Channel& chl) {
        sendDCRTPoly(pk.a, chl);
        sendDCRTPoly(pk.aShoup, chl);
        sendDCRTPoly(pk.b, chl);
        sendDCRTPoly(pk.bShoup, chl);
    };

    template <typename DCRTPoly>
    void receivePublicKey(const PublicKeyDCRT<DCRTPoly>& pk, Channel& chl) {
        receiveDCRTPoly(pk.a, chl);
        receiveDCRTPoly(pk.aShoup, chl);
        receiveDCRTPoly(pk.b, chl);
        receiveDCRTPoly(pk.bShoup, chl);
    };

    template <typename DCRTPoly>
    void sendPublicKey(const PublicKeyDCRTSeeded<DCRTPoly>& pk, Channel& chl) {
        chl.send(pk.seed);
        sendDCRTPoly(pk.b, chl);
    };

    template <typename DCRTPoly>
    void receivePublicKey(const PublicKeyDCRTSeeded<DCRTPoly>& pk, Channel& chl) {
        chl.recv(pk.seed);
        receiveDCRTPoly(pk.b, chl);
    };

    template <typename DCRTPoly>
    void sendSecretKey(const SecretKeyDCRT<DCRTPoly>& sk, Channel& chl) {
        sendDCRTPoly(sk.s, chl);
        sendDCRTPoly(sk.sShoup, chl);
    };

    template <typename DCRTPoly>
    void receiveSecretKey(const SecretKeyDCRT<DCRTPoly>& sk, Channel& chl) {
        receiveDCRTPoly(sk.s, chl);
        receiveDCRTPoly(sk.sShoup, chl);
    };

    /** Encoding Input Types **/

    template <typename poly>
    void sendEncodingInput(const poly& toSend, Channel& chl) {
        chl.send(toSend.vals, poly::phim);
    };

    template <typename poly>
    void receiveEncodingInput(const poly& toLoad, Channel& chl) {
        chl.recv(toLoad.vals, poly::phim);
    }

    template <typename T, ui32 numModuli, ui32 phim>
    void sendEncodingInput(const Array2d<T, numModuli, phim>& toSend, Channel& chl) {
        for (ui32 i = 0; i < numModuli; i++)
            chl.send(toSend[i], phim);
    }

    template <typename T, ui32 numModuli, ui32 phim>
    void receiveEncodingInput(const Array2d<T, numModuli, phim>& toLoad, Channel& chl) {
        for (ui32 i = 0; i < numModuli; i++)
            chl.recv(toLoad[i], phim);
    }

};  // namespace lbcrypto ends
#endif
