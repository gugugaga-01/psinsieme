/*
    Classes for application level ole
*/

#ifndef LBCRYPTO_PKE_OLE
#define LBCRYPTO_PKE_OLE

#include "../../../third_party/cryptoTools/cryptoTools/Common/Defines.h"
#include "../../../third_party/cryptoTools/cryptoTools/Common/Timer.h"
#include "../../../third_party/cryptoTools/cryptoTools/Common/Log.h"

#include "../../../third_party/cryptoTools/cryptoTools/Network/Channel.h"
#include "../../../third_party/cryptoTools/cryptoTools/Network/Session.h"
#include "../../../third_party/cryptoTools/cryptoTools/Network/IOService.h"

#include "bfv.h"
#include "gazelle-network.h"

using namespace std; 
using namespace osuCryptoNew;

namespace lbcrypto {

    //
    // VOLE 
    //

    template <typename encoding_input_t>
    class VOLESenderInput {
    public:

        ui32 numBlocks;  // num blocks
        // each block is in one ciphertext
        vector<encoding_input_t> aBlocks;  // [num blocks][block length]
        vector<encoding_input_t> bBlocks;  // [num blocks][block length]

        VOLESenderInput(const vector<encoding_input_t>& as, const vector<encoding_input_t>& bs) 
            : numBlocks(as.size()), aBlocks(as), bBlocks(bs) { ASSERT_DEBUG(as.size() == bs.size()); };
    
        
        void send(osuCryptoNew::Channel& chl) const {
            chl.send(numBlocks);
            for (ui32 i = 0; i < numBlocks; i++) {
                sendEncodingInput(aBlocks[i], chl);
                sendEncodingInput(bBlocks[i], chl);
            }
        }

        static VOLESenderInput<encoding_input_t> recv(osuCryptoNew::Channel& chl) {
            ui32 nB; chl.recv(nB);
            vector<encoding_input_t> aB(nB), bB(nB);
            for (ui32 i = 0; i < nB; i++) {
                receiveEncodingInput(aB[i], chl);
                receiveEncodingInput(bB[i], chl);
            }
            return VOLESenderInput(aB, bB);
        }

        template <typename encoding_context_t>
        static VOLESenderInput<typename encoding_context_t::encoding_input_t>
        random(const ui32 num_blocks) {
            vector<encoding_input_t> alpha_plain(num_blocks);
            vector<encoding_input_t> beta_plain(num_blocks);
            for (ui32 i = 0; i < alpha_plain.size(); i++) {
                alpha_plain[i] = encoding_context_t::generateRandomInput();
                beta_plain[i] = encoding_context_t::generateRandomInput();
            }
            return VOLESenderInput(alpha_plain, beta_plain);
        }
    };

    template <typename IntType>
    class VOLEReceiverInput {
    public:
        // ui32 numBlocks;  // number of blocks to expect in the output
        // vector<IntType> x;  // [num VOLEs]
        IntType x;

        // VOLEReceiverInput(const vector<IntType>& in) : numBlocks(in.size()), x(in) {};
        VOLEReceiverInput(const IntType& in) : x(in) {};
    };

    template <typename encoding_input_t>
    class VOLEReceiverOutput {
    public:
        ui32 numBlocks;  // vole output is broken into blocks
        vector<encoding_input_t> cBlocks;  // [num blocks][block length]

        VOLEReceiverOutput() {};
        VOLEReceiverOutput(const ui32 numBs) 
            : numBlocks(numBs), cBlocks(numBs) {};
        VOLEReceiverOutput(const vector<encoding_input_t>& in) 
            : numBlocks(in.size()), cBlocks(in) {};
    
        void send(osuCryptoNew::Channel& chl) const {
            chl.send(numBlocks);
            for (ui32 i = 0; i < numBlocks; i++)
                chl.send(cBlocks[i].vals, encoding_input_t::phim);
        }

        static VOLEReceiverOutput<encoding_input_t> receive(osuCryptoNew::Channel& chl) {
            ui32 blocks; chl.recv(blocks);
            vector<encoding_input_t> toRecv(blocks);
            for (ui32 i = 0; i < blocks; i++)
                chl.recv(toRecv[i].vals, encoding_input_t::phim);
            return VOLEReceiverOutput<encoding_input_t>(toRecv);
        };

        static bool eq(
            VOLEReceiverOutput<encoding_input_t>& left,
            VOLEReceiverOutput<encoding_input_t>& right
        ) {
            if (left.numBlocks != right.numBlocks) {
                cout << "Size mismatch!\n";
                cout << left.numBlocks << " != " << right.numBlocks << endl;
                return false;
            }
            for (ui32 n = 0; n < left.numBlocks; n++)
                for (ui32 i = 0; i < encoding_input_t::phim; i++)
                    if (left.cBlocks[n][i] != right.cBlocks[n][i]) {
                        cout << "VOLE mismatch\n";
                        cout << n << " " << i << endl;
                        cout << left.cBlocks[n][i] << " " << right.cBlocks[n][i] << endl;
                        return false;
                    }
            return true;
        }
    };

    template <typename SchemeType>
    class PreprocessedSenderVOLEBlock {
    public:

        using DCRTPoly = typename SchemeType::DCRTPoly;
        using encoding_input_t = typename SchemeType::encoding_input_t;

        DCRTPoly u;
        DCRTPoly zeroA, zeroB;
        DCRTPoly alpha, beta;

        PreprocessedSenderVOLEBlock() {};

        void load(
            const encoding_input_t& aInput,
            const encoding_input_t& bInput,
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme   
        ) {
            alpha = scheme.encodePlainMult(aInput);

            beta = scheme.packed_encode(bInput);
            beta *= scheme.deltas;
            // Leaving beta in coefficient representation
            // Saves an NTT

            scheme.sample_error(u);
            u.ToEval(scheme.ntt_context);
            zeroA = mod_mul_shoup(u, pk.a, pk.aShoup); 
            zeroB = mod_mul_shoup(u, pk.b, pk.bShoup); 
        }
    };

    class VOLESender {
    public:

        template <typename DCRTPolyType>
        static inline void multAddInPlace(const DCRTPolyType& a, DCRTPolyType& x, DCRTPolyType& res) {
            using RingType = typename DCRTPolyType::RingType;

            constexpr ui32 phim = DCRTPolyType::phim;
            constexpr ui32 numLimbs = DCRTPolyType::numLimbs;

            for (ui32 limbInd = 0; limbInd < numLimbs; limbInd++)
                for (ui32 i = 0; i < phim; i++)
                    res[limbInd][i] += RingType::mod_mul(x[limbInd][i], a[limbInd][i], limbInd);
        }

        template <typename SchemeType>
        static inline void online_loop(
            typename SchemeType::CompressedCiphertext& cpXA,
            PreprocessedSenderVOLEBlock<SchemeType>& senderInput,
            const typename SchemeType::Ciphertext& encXA,
            const SchemeType& scheme
        ) {
            multAddInPlace(encXA.a, senderInput.alpha, senderInput.zeroA);
            senderInput.zeroA.ToCoeff(scheme.ntt_context);
            cpXA.a = scheme.dcrt_params.compressDCRTPoly(senderInput.zeroA);

            multAddInPlace(encXA.b, senderInput.alpha, senderInput.zeroB);
            senderInput.zeroB.ToCoeff(scheme.ntt_context);
            senderInput.zeroB += senderInput.beta;
            cpXA.b = scheme.dcrt_params.compressDCRTPoly(senderInput.zeroB);
        }

        template <typename SchemeType>
        static inline void online_thrd(
            const VOLESenderInput<typename SchemeType::encoding_input_t>& input, 
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using Ciphertext = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            chl.send(input.numBlocks);

            vector<PreprocessedSenderVOLEBlock<SchemeType>> blocks(input.numBlocks);
            vector<CompressedCiphertext> cpXAs(input.numBlocks);

            Ciphertext encXA;
            receiveCiphertext(encXA, chl);     

            PARALLEL_FOR
            for (ui32 i = 0; i < input.numBlocks; i++) {
                blocks[i].load(input.aBlocks[i], input.bBlocks[i], pk, scheme);
                VOLESender::online_loop(cpXAs[i], blocks[i], encXA, scheme);
            }

            sendCiphertextVector(cpXAs, chl);
        };

        template <typename SchemeType>
        static inline void online_thrd_comm_opt(
            const VOLESenderInput<typename SchemeType::encoding_input_t>& input, 
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using SeededCiphertext = typename SchemeType::SeededCiphertext;
            using Ciphertext = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            chl.send(input.numBlocks);

            vector<PreprocessedSenderVOLEBlock<SchemeType>> blocks(input.numBlocks);
            vector<CompressedCiphertext> cpXAs(input.numBlocks);

            SeededCiphertext encXASeeded;
            receiveCiphertext(encXASeeded, chl);     

            Ciphertext encXA = encXASeeded.expand();

            PARALLEL_FOR
            for (ui32 i = 0; i < input.numBlocks; i++) {
                blocks[i].load(input.aBlocks[i], input.bBlocks[i], pk, scheme);
                VOLESender::online_loop(cpXAs[i], blocks[i], encXA, scheme);
            }

            sendCiphertextVector(cpXAs, chl);
        };

        template <typename SchemeType>
        static inline void online(
            const VOLESenderInput<typename SchemeType::encoding_input_t>& input, 
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using Ciphertext = typename SchemeType::Ciphertext;
            // using SeededCiphertext = typename SchemeType::SeededCiphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            chl.send(input.numBlocks);

            PreprocessedSenderVOLEBlock<SchemeType> currentBlock;
            currentBlock.load(input.aBlocks[0], input.bBlocks[0], pk, scheme);

            Ciphertext encXA;
            receiveCiphertext(encXA, chl);     

            CompressedCiphertext cpXA;
            for (ui32 rep = 0; rep < input.numBlocks-1; rep++) {
                VOLESender::online_loop(cpXA, currentBlock, encXA, scheme);
                asyncSendCiphertext(cpXA, chl);
                currentBlock.load(input.aBlocks[rep+1], input.bBlocks[rep+1], pk, scheme);
            }

            // Finish off evaluation
            VOLESender::online_loop(cpXA, currentBlock, encXA, scheme);

            // send cpXA
            sendCiphertext(cpXA, chl);
        };

        template <typename SchemeType>
        static inline void online_comm_opt(
            const VOLESenderInput<typename SchemeType::encoding_input_t>& input, 
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using Ciphertext = typename SchemeType::Ciphertext;
            using SeededCiphertext = typename SchemeType::SeededCiphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            chl.send(input.numBlocks);

            PreprocessedSenderVOLEBlock<SchemeType> currentBlock;
            currentBlock.load(input.aBlocks[0], input.bBlocks[0], pk, scheme);

            SeededCiphertext encXASeeded;
            receiveCiphertext(encXASeeded, chl);     

            Ciphertext encXA = encXASeeded.expand();

            CompressedCiphertext cpXA;
            for (ui32 rep = 0; rep < input.numBlocks-1; rep++) {
                VOLESender::online_loop(cpXA, currentBlock, encXA, scheme);
                asyncSendCiphertext(cpXA, chl);
                currentBlock.load(input.aBlocks[rep+1], input.bBlocks[rep+1], pk, scheme);
            }

            // Finish off evaluation
            VOLESender::online_loop(cpXA, currentBlock, encXA, scheme);

            // send cpXA
            sendCiphertext(cpXA, chl);
        };


        //
        // Optimized batching for many short VOLE's
        //

        template <typename encoding_input_t>
        static bool check_same_block_length(
            const vector<VOLESenderInput<encoding_input_t>>& input
        ) {
            const ui32 numBlocks = input[0].numBlocks;
            for (ui32 i = 1; i < input.size(); i++)
                if (input[i].numBlocks != numBlocks)
                    return false;

            return true;
        }

        template <typename SchemeType>
        static inline void online_many(
            const vector<VOLESenderInput<typename SchemeType::encoding_input_t>>& input,
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme,
            osuCryptoNew::Channel& chl
        ) {

            const ui32 numVOLEs = input.size();

            using Ciphertext = typename SchemeType::Ciphertext;
            // using SeededCiphertext = typename SchemeType::SeededCiphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ASSERT_DEBUG(check_same_block_length(input));

            const ui32 numBlocks = input[0].numBlocks;
            chl.send(numBlocks);

            PreprocessedSenderVOLEBlock<SchemeType> currentBlock;
            Ciphertext encXA;
            // CompressedCiphertext cpXA;
            vector<CompressedCiphertext> cpXA(numBlocks);
            for (ui32 ind = 0; ind < numVOLEs; ind++) {  
                auto& currInput = input[ind];
                currentBlock.load(currInput.aBlocks[0], currInput.bBlocks[0], pk, scheme);
                receiveCiphertext(encXA, chl);   
                for (ui32 rep = 0; rep < numBlocks-1; rep++) {
                    VOLESender::online_loop(cpXA[rep], currentBlock, encXA, scheme);
                    asyncSendCiphertext(cpXA[rep], chl);
                    currentBlock.load(currInput.aBlocks[rep+1], currInput.bBlocks[rep+1], pk, scheme);
                }
                // Finish off evaluation
                VOLESender::online_loop(cpXA[numBlocks-1], currentBlock, encXA, scheme);
                sendCiphertext(cpXA[numBlocks-1], chl);
            }
        }

        template <typename SchemeType>
        static inline void online_many_thrd(
            const vector<VOLESenderInput<typename SchemeType::encoding_input_t>>& input,
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme,
            osuCryptoNew::Channel& chl
        ) {

            const ui32 numVOLEs = input.size();

            using Ciphertext = typename SchemeType::Ciphertext;
            // using SeededCiphertext = typename SchemeType::SeededCiphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ASSERT_DEBUG(check_same_block_length(input));

            const ui32 numBlocks = input[0].numBlocks;
            chl.send(input[0].numBlocks);

            vector<vector<CompressedCiphertext>> enc_result(numVOLEs, vector<CompressedCiphertext>(numBlocks));

            vector<vector<PreprocessedSenderVOLEBlock<SchemeType>>> blocks(numVOLEs,
                vector<PreprocessedSenderVOLEBlock<SchemeType>>(numBlocks));

            vector<Ciphertext> enc_input;
            receiveCiphertextVector(enc_input, chl);

            PARALLEL_FOR
            for (ui32 vind = 0; vind < numVOLEs; vind++) {
                for (ui32 bInd = 0; bInd < numBlocks; bInd++) {
                    blocks[vind][bInd].load(input[vind].aBlocks[bInd], input[vind].bBlocks[bInd], pk, scheme);
                    online_loop(enc_result[vind][bInd], blocks[vind][bInd], enc_input[vind], scheme);
                }
            }

            sendCiphertextMatrix(enc_result, chl);
        }

        template <typename SchemeType>
        static inline void online_many_thrd_comm_opt(
            const vector<VOLESenderInput<typename SchemeType::encoding_input_t>>& input,
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme,
            osuCryptoNew::Channel& chl
        ) {

            const ui32 numVOLEs = input.size();

            using Ciphertext = typename SchemeType::Ciphertext;
            using SeededCiphertext = typename SchemeType::SeededCiphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ASSERT_DEBUG(check_same_block_length(input));

            const ui32 numBlocks = input[0].numBlocks;
            chl.send(input[0].numBlocks);

            vector<vector<CompressedCiphertext>> enc_result(numVOLEs, vector<CompressedCiphertext>(numBlocks));

            vector<vector<PreprocessedSenderVOLEBlock<SchemeType>>> blocks(numVOLEs,
                vector<PreprocessedSenderVOLEBlock<SchemeType>>(numBlocks));

            vector<SeededCiphertext> enc_input_seeded;
            receiveCiphertextVector(enc_input_seeded, chl);

            PARALLEL_FOR
            for (ui32 vind = 0; vind < numVOLEs; vind++) {
                Ciphertext enc_input = enc_input_seeded[vind].expand();
                for (ui32 bInd = 0; bInd < numBlocks; bInd++) {
                    blocks[vind][bInd].load(input[vind].aBlocks[bInd], input[vind].bBlocks[bInd], pk, scheme);
                    online_loop(enc_result[vind][bInd], blocks[vind][bInd], enc_input, scheme);
                }
            }

            sendCiphertextMatrix(enc_result, chl);
        }

    };

    class VOLEReceiver {
    public:

        template <typename SchemeType>
        static inline typename SchemeType::Ciphertext preprocessReceiverInput(
            const typename SchemeType::plaintext_type& input, 
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme
        ) {
            auto pt = scheme.encoding_context.packed_encode(input);
            return scheme.Encrypt(sk, pt);
        }

        template <typename SchemeType>
        static inline typename SchemeType::SeededCiphertext preprocessReceiverInputSeeded(
            const typename SchemeType::plaintext_type& input, 
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme
        ) {
            auto pt = scheme.encoding_context.packed_encode(input);
            return scheme.EncryptSeeded(sk, pt);
        }

        template <typename SchemeType>
        static inline typename SchemeType::encoding_input_t postprocess_block(
            typename SchemeType::CompressedCiphertext& encResult,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme
        ) {
            encResult.a.ToEval(scheme.ntt_context.ntt_contexts[0]);
            return scheme.Decrypt(sk, encResult);
        }
        

        template <typename SchemeType>
        static VOLEReceiverOutput<typename SchemeType::encoding_input_t> online(
            const VOLEReceiverInput<typename SchemeType::plaintext_type>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {

            using encoding_input_t = typename SchemeType::encoding_input_t;
            // using FreshCTType = typename SchemeType::SeededCiphertext;
            using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ui32 numBlocks; chl.recv(numBlocks);
            VOLEReceiverOutput<encoding_input_t> output(numBlocks);
            

            // prep input 0
            FreshCTType toSend = preprocessReceiverInput(input.x, sk, scheme);
            sendCiphertext(toSend, chl);

            CompressedCiphertext encResult;
            for (ui32 rep = 0; rep < numBlocks; rep++) {
                receiveCiphertext(encResult, chl);
                output.cBlocks[rep] = VOLEReceiver::postprocess_block(encResult, sk, scheme);
            }
            return output;
        };

        template <typename SchemeType>
        static VOLEReceiverOutput<typename SchemeType::encoding_input_t> online_comm_opt(
            const VOLEReceiverInput<typename SchemeType::plaintext_type>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {

            using encoding_input_t = typename SchemeType::encoding_input_t;
            using FreshCTType = typename SchemeType::SeededCiphertext;
            // using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ui32 numBlocks; chl.recv(numBlocks);
            VOLEReceiverOutput<encoding_input_t> output(numBlocks);
            

            // prep input 0
            // FreshCTType toSend = preprocessReceiverInput(input.x, sk, scheme);
            FreshCTType toSend = preprocessReceiverInputSeeded(input.x, sk, scheme);
            sendCiphertext(toSend, chl);

            CompressedCiphertext encResult;
            for (ui32 rep = 0; rep < numBlocks; rep++) {
                receiveCiphertext(encResult, chl);
                output.cBlocks[rep] = VOLEReceiver::postprocess_block(encResult, sk, scheme);
            }
            return output;
        };

        template <typename SchemeType>
        static VOLEReceiverOutput<typename SchemeType::encoding_input_t> online_thrd(
            const VOLEReceiverInput<typename SchemeType::plaintext_type>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {

            using encoding_input_t = typename SchemeType::encoding_input_t;
            // using FreshCTType = typename SchemeType::SeededCiphertext;
            using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ui32 numBlocks; chl.recv(numBlocks);
            VOLEReceiverOutput<encoding_input_t> output(numBlocks);
            
            // prep input 0
            FreshCTType toSend = preprocessReceiverInput(input.x, sk, scheme);
            sendCiphertext(toSend, chl);

            vector<CompressedCiphertext> encResults;
            receiveCiphertextVector(encResults, chl);

            PARALLEL_FOR
            for (ui32 rep = 0; rep < numBlocks; rep++)
                output.cBlocks[rep] = VOLEReceiver::postprocess_block(encResults[rep], sk, scheme);

            return output;
        };

        //
        // Optimized batching for many short VOLE's
        //

        template <typename SchemeType>
        static vector<VOLEReceiverOutput<typename SchemeType::encoding_input_t>>
        online_many(
            const vector<VOLEReceiverInput<typename SchemeType::plaintext_type>>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using encoding_input_t = typename SchemeType::encoding_input_t;
            // using FreshCTType = typename SchemeType::SeededCiphertext;
            using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ui32 numBlocks; chl.recv(numBlocks);
            const ui32 numVOLEs = input.size();

            vector<VOLEReceiverOutput<encoding_input_t>> output;
            output.reserve(numVOLEs);

            FreshCTType toSend = preprocessReceiverInput(input[0].x, sk, scheme);
            FreshCTType toSendNext;
            CompressedCiphertext encResult;
            for (ui32 ind = 0; ind < numVOLEs-1; ind++) {
                asyncSendCiphertext(toSend, chl);

                toSendNext = preprocessReceiverInput(input[ind+1].x, sk, scheme);

                output.push_back(VOLEReceiverOutput<encoding_input_t>(numBlocks));

                for (ui32 rep = 0; rep < numBlocks; rep++) {
                    receiveCiphertext(encResult, chl);
                    output[ind].cBlocks[rep] = VOLEReceiver::postprocess_block(encResult, sk, scheme);
                }
                toSend = toSendNext;
            }

            sendCiphertext(toSend, chl);

            output.push_back(VOLEReceiverOutput<encoding_input_t>(numBlocks));

            for (ui32 rep = 0; rep < numBlocks; rep++) {
                receiveCiphertext(encResult, chl);
                output[numVOLEs-1].cBlocks[rep] = VOLEReceiver::postprocess_block(encResult, sk, scheme);
            }

            return output;
        };

        template <typename SchemeType>
        static vector<VOLEReceiverOutput<typename SchemeType::encoding_input_t>>
        online_many_thrd(
            const vector<VOLEReceiverInput<typename SchemeType::plaintext_type>>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using encoding_input_t = typename SchemeType::encoding_input_t;
            // using FreshCTType = typename SchemeType::SeededCiphertext;
            using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ui32 numBlocks; chl.recv(numBlocks);
            const ui32 numVOLEs = input.size();

            vector<FreshCTType> enc_input(numVOLEs);
            PARALLEL_FOR
            for (ui32 i = 0; i < numVOLEs; i++)
                enc_input[i] = preprocessReceiverInput(input[i].x, sk, scheme);
            sendCiphertextVector(enc_input, chl);

            vector<VOLEReceiverOutput<encoding_input_t>> output(numVOLEs);

            vector<vector<CompressedCiphertext>> enc_output;
            receiveCiphertextMatrix(enc_output, chl);

            PARALLEL_FOR
            for (ui32 i = 0; i < numVOLEs; i++) {
                output[i] = VOLEReceiverOutput<encoding_input_t>(numBlocks);
                for (ui32 b = 0; b < numBlocks; b++)
                    output[i].cBlocks[b] = postprocess_block(enc_output[i][b], sk, scheme);
            }
            return output;
        };

        template <typename SchemeType>
        static vector<VOLEReceiverOutput<typename SchemeType::encoding_input_t>>
        online_many_thrd_comm_opt(
            const vector<VOLEReceiverInput<typename SchemeType::plaintext_type>>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using encoding_input_t = typename SchemeType::encoding_input_t;
            using FreshCTType = typename SchemeType::SeededCiphertext;
            // using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            ui32 numBlocks; chl.recv(numBlocks);
            const ui32 numVOLEs = input.size();

            vector<FreshCTType> enc_input(numVOLEs);
            PARALLEL_FOR
            for (ui32 i = 0; i < numVOLEs; i++)
                enc_input[i] = preprocessReceiverInputSeeded(input[i].x, sk, scheme);
                // enc_input[i] = preprocessReceiverInput(input[i].x, sk, scheme);
            sendCiphertextVector(enc_input, chl);

            vector<VOLEReceiverOutput<encoding_input_t>> output(numVOLEs);

            vector<vector<CompressedCiphertext>> enc_output;
            receiveCiphertextMatrix(enc_output, chl);

            PARALLEL_FOR
            for (ui32 i = 0; i < numVOLEs; i++) {
                output[i] = VOLEReceiverOutput<encoding_input_t>(numBlocks);
                for (ui32 b = 0; b < numBlocks; b++)
                    output[i].cBlocks[b] = postprocess_block(enc_output[i][b], sk, scheme);
            }
            return output;
        };
    };


    template <typename encoding_context_t>
    VOLEReceiverOutput<typename encoding_context_t::encoding_input_t> vole_pt(
        const VOLEReceiverInput<typename encoding_context_t::value_type>& recv_in, 
        const VOLESenderInput<typename encoding_context_t::encoding_input_t>& send_in
    ) {
        using encoding_input_t = typename encoding_context_t::encoding_input_t;

        VOLEReceiverOutput<encoding_input_t> result(send_in.numBlocks);
        for (ui32 rep = 0; rep < send_in.numBlocks; rep++) 
            result.cBlocks[rep] = encoding_context_t::enc_input_sum(
                encoding_context_t::enc_input_prod(send_in.aBlocks[rep], recv_in.x), 
                send_in.bBlocks[rep]
            );
        return result;
    }

    template <typename encoding_context_t>
    vector<VOLEReceiverOutput<typename encoding_context_t::encoding_input_t>> vole_pt(
        const vector<VOLEReceiverInput<typename encoding_context_t::value_type>>& recv_in, 
        const vector<VOLESenderInput<typename encoding_context_t::encoding_input_t>>& send_in
    ) {
        ASSERT_DEBUG(recv_in.size() == send_in.size());

        using encoding_input_t = typename encoding_context_t::encoding_input_t;

        vector<VOLEReceiverOutput<encoding_input_t>> result;
        result.reserve(send_in.size());
        
        for (ui32 i = 0; i < send_in.size(); i++)
            result.push_back(vole_pt<encoding_context_t>(recv_in[i], send_in[i]));

        return result;
    } 


    //
    // BOLE
    //

    template <typename T>
    using BOLESenderInput = VOLESenderInput<T>;

    template <typename T>
    using PreprocessedSenderBOLEBlock = PreprocessedSenderVOLEBlock<T>;

    template <typename encoding_input_t>
    class BOLEReceiverInput {
    public:
        ui32 numBlocks;  // num VOLEs
        vector<encoding_input_t> x;  // [num VOLEs]

        BOLEReceiverInput(const ui32 n) : numBlocks(n), x(n) {};
        BOLEReceiverInput(const vector<encoding_input_t>& in) : numBlocks(in.size()), x(in) {};
   
        void send(osuCryptoNew::Channel& chl) const {
            chl.send(numBlocks);
            for (ui32 i = 0; i < numBlocks; i++)
                chl.send(x[i].vals, encoding_input_t::phim);
        }

        static BOLEReceiverInput<encoding_input_t> receive(osuCryptoNew::Channel& chl) {
            ui32 n; chl.recv(n);
            vector<encoding_input_t> toRecv(n);
            for (ui32 i = 0; i < n; i++)
                chl.recv(toRecv[i].vals, encoding_input_t::phim);
            return BOLEReceiverInput<encoding_input_t>(toRecv);
        };
   
    };

    template <typename T>
    using BOLEReceiverOutput = VOLEReceiverOutput<T>;


    class BOLESender : public VOLESender {
    public:

        template <typename SchemeType>
        static inline void online(
            const BOLESenderInput<typename SchemeType::encoding_input_t>& input, 
            const typename SchemeType::PublicKey& pk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {
            using Ciphertext = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            // begin by prepping iter = 0
            // vector<thread> thrds(2);
            PreprocessedSenderBOLEBlock<SchemeType> currentBlock;
            // currentBlock.load_thrd(thrds, input.aBlocks[0], input.bBlocks[0], pk, scheme);
            currentBlock.load(input.aBlocks[0], input.bBlocks[0], pk, scheme);
            // for (auto& thrd : thrds) thrd.join();

            PreprocessedSenderBOLEBlock<SchemeType> nextBlock;

            Ciphertext encXA;
            // receiveCiphertext(encXA, chl);     

            CompressedCiphertext cpXA;
            for (ui32 rep = 0; rep < input.numBlocks-1; rep++) {
                #ifdef MULTI_THREAD
                auto thrd = thread([&] () {
                // nextBlock.load_thrd(thrds, input.aBlocks[rep+1], input.bBlocks[rep+1], pk, scheme);
                nextBlock.load(input.aBlocks[rep+1], input.bBlocks[rep+1], pk, scheme);
            
                });
                #endif

                // receive input rep
                receiveCiphertext(encXA, chl);     

                BOLESender::online_loop(cpXA, currentBlock, encXA, scheme);

                sendCiphertext(cpXA, chl);

                #ifdef MULTI_THREAD
                thrd.join();
                #endif
                #ifndef MULTI_THREAD
                nextBlock.load(input.aBlocks[rep+1], input.bBlocks[rep+1], pk, scheme);
                #endif
                // for (auto& thrd : thrds) thrd.join();
                currentBlock = nextBlock;
            }

            // receive final input
            receiveCiphertext(encXA, chl);     

            // Finish off evaluation
            BOLESender::online_loop(cpXA, currentBlock, encXA, scheme);

            // send cpXA
            sendCiphertext(cpXA, chl);
        };

    };


    class BOLEReceiver {
    public:

        template <typename SchemeType>
        static inline typename SchemeType::Ciphertext preprocessReceiverInput(
            const typename SchemeType::encoding_input_t& input, 
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme
        ) { return scheme.Encrypt(sk, input); }

        template <typename SchemeType>
        static inline typename SchemeType::SeededCiphertext preprocessReceiverInputSeeded(
            const typename SchemeType::encoding_input_t& input, 
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme
        ) { return scheme.EncryptSeeded(sk, input); }

        template <typename SchemeType>
        static inline typename SchemeType::encoding_input_t postprocess_block(
            typename SchemeType::CompressedCiphertext& encResult,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme
        ) {
            encResult.a.ToEval(scheme.ntt_context.ntt_contexts[0]);
            return scheme.Decrypt(sk, encResult);
        }
        

        template <typename SchemeType>
        static BOLEReceiverOutput<typename SchemeType::encoding_input_t> online(
            const BOLEReceiverInput<typename SchemeType::encoding_input_t>& input,
            const typename SchemeType::SecretKey& sk,
            const SchemeType& scheme, 
            osuCryptoNew::Channel& chl
        ) {

            using encoding_input_t = typename SchemeType::encoding_input_t;
            using FreshCTType = typename SchemeType::Ciphertext;
            using CompressedCiphertext = typename SchemeType::CompressedCiphertext;

            BOLEReceiverOutput<encoding_input_t> output(input.numBlocks);

            // prep input 0
            FreshCTType toSend = preprocessReceiverInput(input.x[0], sk, scheme);
            FreshCTType toSendNext;

            CompressedCiphertext encResult;
            
            for (ui32 rep = 0; rep < input.numBlocks-1; rep++) {
                asyncSendCiphertext(toSend, chl);
                
                #ifdef MULTI_THREAD
                auto thrd = thread([&] () {
                #endif
                    toSendNext = preprocessReceiverInput(input.x[rep+1], sk, scheme);
                #ifdef MULTI_THREAD
                });     
                #endif

                receiveCiphertext(encResult, chl);

                output.cBlocks[rep] = BOLEReceiver::postprocess_block(encResult, sk, scheme);

                #ifdef MULTI_THREAD
                thrd.join();
                #endif
                toSend = toSendNext;
            }

            sendCiphertext(toSend, chl);
            receiveCiphertext(encResult, chl);
            output.cBlocks[input.numBlocks-1] = BOLEReceiver::postprocess_block(encResult, sk, scheme);

            return output;
        };
    };


    template <typename encoding_context_t>
    BOLEReceiverOutput<typename encoding_context_t::encoding_input_t> bole_pt(
        const BOLEReceiverInput<typename encoding_context_t::encoding_input_t>& recv_in, 
        const BOLESenderInput<typename encoding_context_t::encoding_input_t>& send_in
    ) {
        ASSERT_DEBUG(recv_in.numBlocks == send_in.numBlocks);

        using encoding_input_t = typename encoding_context_t::encoding_input_t;

        VOLEReceiverOutput<encoding_input_t> result(send_in.numBlocks);
        for (ui32 rep = 0; rep < send_in.numBlocks; rep++) 
            result.cBlocks[rep] = encoding_context_t::enc_input_sum(
                encoding_context_t::enc_input_prod(send_in.aBlocks[rep], recv_in.x[rep]), 
                send_in.bBlocks[rep]
            );
        return result;
    } 

};


#endif