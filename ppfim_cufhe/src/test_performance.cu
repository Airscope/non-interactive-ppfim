//
// Created by z1y on 2019/9/26.
//

#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <chrono>

#include "cloud.cuh"
#include "user.cuh"
#include "miner.cuh"

void print(const std::vector<std::chrono::milliseconds> &times) {
    int64_t total_times = 0;
    bool first = true;
    std::cout << "[";
    for (auto time : times) {
        if (first) first = false;
        else std::cout << ", ";
        std::cout << time.count();
        total_times += time.count();
    }
    std::cout << "] milliseconds. Average time: " 
              << total_times / (double) times.size() 
              << " milliseconds.\n";
}

int main() {

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

    // main parts

    std::string file_name = "dataset_chess.txt";
    const double min_supp = 0.8;
    int test_times = 5; // Test each protocol 5 times
    int stream_num = kNumSMs;

    std::vector<int> trans_num = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000};
    std::vector<int> items_num = {10, 20, 30, 40, 50, 60, 70};

    for (auto m : trans_num) {

        int n = 20;
        int k = floor(log2((double)m)) + 1;
        int min_supp_count = min_supp * m;

        std::cout << "Trans Number: " << m << ", Items Number: " << n << std::endl;

        // Load data matrix from disk
        std::vector<cufhe::Ptxt *> data_matrix(m);
        for (int i = 0; i < m; ++ i) {
            data_matrix[i] = new cufhe::Ptxt[n];
        }
        ppfim::LoadData(data_matrix, file_name, m, n);

        // Encrypt data matrix
        std::vector<cufhe::Ctxt *> ctxt_data_matrix(m);
        for (int i = 0; i < m; ++i) {
            ctxt_data_matrix[i] = new cufhe::Ctxt[n];
        }
        ppfim::EncryptData(ctxt_data_matrix, m, n, data_matrix, pri_key);

        // Get a ciphertext minimum support count
        cufhe::Ctxt *ctxt_min_supp_count = new cufhe::Ctxt[k];
        ppfim::CtxtMinSuppCount(ctxt_min_supp_count, k, min_supp_count, pri_key);

        // Get the ciphertext and the plaintext query
        cufhe::Ptxt *ptxt_query = new cufhe::Ptxt[n];
        ppfim::PlaintextQuery(ptxt_query, n);
        cufhe::Ctxt *ctxt_query = new cufhe::Ctxt[n];
        ppfim::CiphertextQuery(ctxt_query, n, pri_key);

        // Allocate memory for the mining result;
        cufhe::Ctxt *mining_result = new cufhe::Ctxt;
        
        // Generate plaintext and ciphertext 0, 1
        cufhe::Ptxt *ptxt_one = new cufhe::Ptxt;
        cufhe::Ctxt *ctxt_one = new cufhe::Ctxt;
        cufhe::Ptxt *ptxt_zero = new cufhe::Ptxt;
        cufhe::Ctxt *ctxt_zero = new cufhe::Ctxt;
        ptxt_one->message_ = 1;
        ptxt_zero->message_ = 0;
        cufhe::Encrypt(*ctxt_zero, *ptxt_zero, pri_key);
        cufhe::Encrypt(*ctxt_one, *ptxt_one, pri_key);

        std::chrono::high_resolution_clock::time_point time_start, time_finish;
        std::vector<std::chrono::milliseconds> time_diffs_p1;
        std::vector<std::chrono::milliseconds> time_diffs_p2;

        for (int j = 0; j < test_times; ++j) {

            // Test protocol 1's performance
            time_start = std::chrono::high_resolution_clock::now();
            ppfim::FreqItemsetMiningFirst(*mining_result,
                                          ctxt_data_matrix,
                                          m,
                                          n,
                                          ctxt_min_supp_count,
                                          ctxt_query,
                                          k,
                                          *ctxt_zero,
                                          *ctxt_one,
                                          stream,
                                          stream_num);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p1.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));

            // Test protocol 2's performance
            time_start = std::chrono::high_resolution_clock::now(); 
            ppfim::FreqItemsetMiningSecond(*mining_result,
                                           ctxt_data_matrix,
                                           m,
                                           n,
                                           ctxt_min_supp_count,
                                           ptxt_query,
                                           k,
                                           *ctxt_zero,
                                           *ctxt_one,
                                           stream,
                                           stream_num);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p2.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));
        }

        // Print info
        std::cout << "Protocol 1 time used: ";
        print(time_diffs_p1);

        std::cout << "Protocol 2 time used: ";
        print(time_diffs_p2);

        // Clean up all pointers
        for (int i = 0; i < m; ++ i) {
            delete [] (data_matrix[i]);
        }
        for (int i = 0; i < m; ++i) {
            delete [] (ctxt_data_matrix[i]);
        }

        delete [] ctxt_min_supp_count;
        delete [] ptxt_query;
        delete [] ctxt_query;
        delete mining_result;
        delete ptxt_one;
        delete ptxt_zero;
        delete ctxt_one;
        delete ctxt_zero;
    }

    for (auto n : items_num) {

        int m = 1000;
        int k = floor(log2((double)m)) + 1;
        int min_supp_count = min_supp * m;

        std::cout << "Trans Number: " << m << ", Items Number: " << n << std::endl;

        // Load data matrix from disk
        std::vector<cufhe::Ptxt *> data_matrix(m);
        for (int i = 0; i < m; ++ i) {
            data_matrix[i] = new cufhe::Ptxt[n];
        }
        ppfim::LoadData(data_matrix, file_name, m, n);

        // Encrypt data matrix
        std::vector<cufhe::Ctxt *> ctxt_data_matrix(m);
        for (int i = 0; i < m; ++i) {
            ctxt_data_matrix[i] = new cufhe::Ctxt[n];
        }
        ppfim::EncryptData(ctxt_data_matrix, m, n, data_matrix, pri_key);

        // Get a ciphertext minimum support count
        cufhe::Ctxt *ctxt_min_supp_count = new cufhe::Ctxt[k];
        ppfim::CtxtMinSuppCount(ctxt_min_supp_count, k, min_supp_count, pri_key);

        // Get the ciphertext and the plaintext query
        cufhe::Ptxt *ptxt_query = new cufhe::Ptxt[n];
        ppfim::PlaintextQuery(ptxt_query, n);
        cufhe::Ctxt *ctxt_query = new cufhe::Ctxt[n];
        ppfim::CiphertextQuery(ctxt_query, n, pri_key);

        // Allocate memory for the mining result;
        cufhe::Ctxt *mining_result = new cufhe::Ctxt;
        
        // Generate plaintext and ciphertext 0, 1
        cufhe::Ptxt *ptxt_one = new cufhe::Ptxt;
        cufhe::Ctxt *ctxt_one = new cufhe::Ctxt;
        cufhe::Ptxt *ptxt_zero = new cufhe::Ptxt;
        cufhe::Ctxt *ctxt_zero = new cufhe::Ctxt;
        ptxt_one->message_ = 1;
        ptxt_zero->message_ = 0;
        cufhe::Encrypt(*ctxt_zero, *ptxt_zero, pri_key);
        cufhe::Encrypt(*ctxt_one, *ptxt_one, pri_key);

        std::chrono::high_resolution_clock::time_point time_start, time_finish;
        std::vector<std::chrono::milliseconds> time_diffs_p1;
        std::vector<std::chrono::milliseconds> time_diffs_p2;

        for (int j = 0; j < test_times; ++j) {

            // Test protocol 1's performance
            time_start = std::chrono::high_resolution_clock::now();
            ppfim::FreqItemsetMiningFirst(*mining_result,
                                          ctxt_data_matrix,
                                          m,
                                          n,
                                          ctxt_min_supp_count,
                                          ctxt_query,
                                          k,
                                          *ctxt_zero,
                                          *ctxt_one,
                                          stream,
                                          stream_num);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p1.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));

            // Test protocol 2's performance
            time_start = std::chrono::high_resolution_clock::now(); 
            ppfim::FreqItemsetMiningSecond(*mining_result,
                                           ctxt_data_matrix,
                                           m,
                                           n,
                                           ctxt_min_supp_count,
                                           ptxt_query,
                                           k,
                                           *ctxt_zero,
                                           *ctxt_one,
                                           stream,
                                           stream_num);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p2.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));
        }

        // Print info
        std::cout << "Protocol 1 time used: ";
        print(time_diffs_p1);

        std::cout << "Protocol 2 time used: ";
        print(time_diffs_p2);

        // Clean up all pointers
        for (int i = 0; i < m; ++ i) {
            delete [] (data_matrix[i]);
        }
        for (int i = 0; i < m; ++i) {
            delete [] (ctxt_data_matrix[i]);
        }

        delete [] ctxt_min_supp_count;
        delete [] ptxt_query;
        delete [] ctxt_query;
        delete mining_result;
        delete ptxt_one;
        delete ptxt_zero;
        delete ctxt_one;
        delete ctxt_zero;
    }


    std::cout << "Cleaning up Data on GPU ..." << std::endl;
    
    for (int i = 0; i < kNumSMs; ++i) {
        stream[i].Destroy();
    }

    delete [] stream;
    
    cufhe::CleanUp();

    return 0;
}
