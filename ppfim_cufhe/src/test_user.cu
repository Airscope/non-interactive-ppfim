//
// Created by z1y on 2019/9/27.
//

#include <iostream>
#include <vector>
#include <cmath>
#include <cassert>

#include "cufhe_gpu.cuh"

#include "user.cuh"
#include "cloud.cuh"

void print(const cufhe::Ptxt* ptxt, uint32_t length) {
    bool first = true;
    for (int i = 0;i < length; ++i) {
        if (first) first = false;
        else std::cout << ", ";
        std::cout << ptxt[i].message_;
    }
    std::cout << "\n";
}


void print(const cufhe::Ctxt* ctxts, uint32_t length, 
        const cufhe::PriKey &pri_key) {
    cufhe::Ptxt* ptxts = new cufhe::Ptxt[length];
    for (int i = 0; i < length; ++ i)
        cufhe::Decrypt(ptxts[i], ctxts[i], pri_key);
    print(ptxts, length);
    delete [] ptxts;
}


void TestLoadData() {
    std::cout << "Test function LoadData(), loading a 10*10 matrix" << std::endl;

    std::vector<cufhe::Ptxt *> data_matrix(10);
    for (int i = 0; i < 10; ++ i) {
        data_matrix[i] = new cufhe::Ptxt[10];
    }
    
    std::string file_name = "dataset_chess.txt";
    ppfim::LoadData(data_matrix, file_name, 10, 10);
    for (int i = 0; i < 10; ++ i) {
        print(data_matrix[i], 10);
    }

    for (int i = 0; i < 10; ++ i) {
        delete [] (data_matrix[i]);
    }

    std::cout << "PASS" << std::endl;
}

void TestCtxtMinSuppCount(const cufhe::PriKey &pri_key,
                          const cufhe::PubKey &pub_key) {
    int test_times = 10, length, min_supp_count, rows;
    double min_supp;
    bool correct = true;
    std::cout << "Test ctxt min supp count " << test_times << " times" << std::endl;
    while (test_times --) {
        rows = rand() % 1000 + 1000;
        length = floor(log2((double)rows)) + 1;
        min_supp = (rand() % 100) / 100.0;
        min_supp_count = (int)(rows * min_supp);

        cufhe::Ptxt *ptxt_min_supp_count = new cufhe::Ptxt[length];
        cufhe::Ctxt *ctxt_min_supp_count = new cufhe::Ctxt[length];
        cufhe::Ptxt *decrypted = new cufhe::Ptxt[length];

        ppfim::DecToBin(ptxt_min_supp_count, min_supp_count, length);

        ppfim::CtxtMinSuppCount(ctxt_min_supp_count,
                                length,
                                min_supp_count,
                                pri_key);

        for (int i = 0; i < length; ++i) {
            cufhe::Decrypt(decrypted[i], ctxt_min_supp_count[i], pri_key);
            correct &= (decrypted[i].message_
                        == ptxt_min_supp_count[i].message_);
        }

        delete [] ptxt_min_supp_count;
        delete [] ctxt_min_supp_count;
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
    TestLoadData();
    TestCtxtMinSuppCount(pri_key, pub_key);

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
