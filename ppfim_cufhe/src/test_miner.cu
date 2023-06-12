//
// Created by z1y on 2019/9/25.
//

#include <iostream>
#include <tfhe/tfhe.h>

#include "miner.cuh"

void TestQuery(const cufhe::PriKey &pri_key,
               const cufhe::PubKey &pub_key) {

    int test_times = 10, length;
    bool correct = true;
    std::cout << "Test ciphertext (plaintext) query " << test_times << " times" << std::endl;
    while (test_times --) {
        length = rand() % 20 + 1;

        cufhe::Ptxt *ptxt_query = new cufhe::Ptxt[length];
        cufhe::Ctxt *ctxt_query = new cufhe::Ctxt[length];
        cufhe::Ptxt *decrypted = new cufhe::Ptxt[length];

        ppfim::PlaintextQuery(ptxt_query, length);

        ppfim::CiphertextQuery(ctxt_query, length, pri_key);

        for (int i = 0; i < length; ++i) {
            cufhe::Decrypt(decrypted[i], ctxt_query[i], pri_key);
            correct &= (decrypted[i].message_
                        == ptxt_query[i].message_);
        }

        delete [] ptxt_query;
        delete [] ctxt_query;
        delete [] decrypted;
    }
    std::cout << (correct? "PASS" : "FAIL") << std::endl;
}

void TestAll() {

    cudaSetDevice(0);
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    const uint32_t kNumSMs = prop.multiProcessorCount; // stream multiprocessor

    cufhe::SetSeed();

    cufhe::PriKey pri_key;
    cufhe::PubKey pub_key;

    cufhe::Synchronize();

    std::cout << "Key Generating..." << std::endl;
    cufhe::KeyGen(pub_key, pri_key);

    std::cout << "Initializing Data on GPU ..." << std::endl;
    cufhe::Initialize(pub_key);

    cufhe::Stream* stream = new cufhe::Stream[kNumSMs];
    for (int i = 0; i < kNumSMs; ++i) {
        stream[i].Create();
    }

    // Test algorithms...
    TestQuery(pri_key, pub_key);

    for (int i = 0; i < kNumSMs; ++i) {
        stream[i].Destroy();
    }

    delete [] stream;
    
    std::cout << "Cleaning up Data on GPU ..." << std::endl;
    cufhe::CleanUp();

}

int main() {
    TestAll();
    return 0;
}



