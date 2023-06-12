//
// Created by z1y on 2019/9/27.
//

#include <iostream>
#include <vector>
#include <cmath>
#include <cassert>

#include "cufhe_gpu.cuh"

#include "cloud.cuh"

void NandCheck(cufhe::Ptxt &out, const cufhe::Ptxt &in0, const cufhe::Ptxt &in1) {
    out.message_ = 1 - in0.message_ * in1.message_;
}


void OrCheck(cufhe::Ptxt &out, const cufhe::Ptxt &in0, const cufhe::Ptxt &in1) {
    out.message_ = (in0.message_ + in1.message_) > 0;
}


void AndCheck(cufhe::Ptxt &out, const cufhe::Ptxt &in0, const cufhe::Ptxt &in1) {
    out.message_ = in0.message_ * in1.message_;
}


void XorCheck(cufhe::Ptxt &out, const cufhe::Ptxt &in0, const cufhe::Ptxt &in1) {
    out.message_ = (in0.message_ + in1.message_) & 0x1;
}


void NotCheck(cufhe::Ptxt &out, const cufhe::Ptxt &in0) {
    out.message_ = 1 - in0.message_;
}


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


void TrivialSubsetTesting(cufhe::Ptxt &out,
                          const cufhe::Ptxt *query,
                          const cufhe::Ptxt *trans,
                          uint32_t length) {
    out.message_ = 1;
    cufhe::Ptxt *tmp = new cufhe::Ptxt;
    for (int i = 0; i < length; ++i) {
        NotCheck(*tmp, query[i]);
        OrCheck(*tmp, *tmp, trans[i]);
        AndCheck(out, out, *tmp);
    }
    delete tmp;
}


void TrivialFreqItemsetMining(cufhe::Ptxt &out,
                              const std::vector<cufhe::Ptxt *>& ptxt_data_matrix,
                              uint32_t rows,
                              uint32_t cols,
                              const cufhe::Ptxt *ptxt_query,
                              uint32_t min_supp_count) {

    cufhe::Ptxt *subset_test_result = new cufhe::Ptxt;
    uint32_t counter = 0;
    for (int i = 0; i < rows; ++ i) {
        TrivialSubsetTesting(*subset_test_result, ptxt_query, ptxt_data_matrix[i], cols);
        counter += subset_test_result->message_;
    }

    delete subset_test_result;
    out.message_ = (counter < min_supp_count? 1 : 0);
}


void TestSecureSubsetTesting(const cufhe::PubKey &pub_key,
                             const cufhe::PriKey &pri_key,
                             cufhe::Stream* stream,
                             uint32_t stream_num) {
    int test_times = 20;
    std::cout << "Test (somewhat) secure subset testing algorithm " << test_times << " times...\n";
    bool correct = true, correct_secure = true, correct_somewhat = true;
    uint32_t length;
    for (int i = 0; i < test_times; ++i) {
        length = rand() % 100 + 1;
        cufhe::Ptxt *query = new cufhe::Ptxt[length];
        cufhe::Ptxt *trans = new cufhe::Ptxt[length];
        cufhe::Ptxt *ptxt_result = new cufhe::Ptxt;
        cufhe::Ptxt *result_decrypted = new cufhe::Ptxt;
        cufhe::Ptxt *result_somewhat_decrypted = new cufhe::Ptxt;
        cufhe::Ptxt *ptxt_tmp = new cufhe::Ptxt;

        cufhe::Ctxt *ctxt_query = new cufhe::Ctxt[length];
        cufhe::Ctxt *ctxt_trans = new cufhe::Ctxt[length];
        cufhe::Ctxt *ctxt_result = new cufhe::Ctxt;
        cufhe::Ctxt *ctxt_somewhat_result = new cufhe::Ctxt;
        cufhe::Ctxt *ctxt_one = new cufhe::Ctxt;

        for (int j = 0; j < length; ++j) {
            query[j].message_ = rand() % cufhe::Ptxt::kPtxtSpace;
            cufhe::Encrypt(ctxt_query[j], query[j], pri_key);
            trans[j].message_ = rand() % cufhe::Ptxt::kPtxtSpace;
            cufhe::Encrypt(ctxt_trans[j], trans[j], pri_key);
        }

        // Trivial model
        TrivialSubsetTesting(*ptxt_result, query, trans, length);

        // Secure model
        ptxt_tmp->message_ = 1;
        cufhe::Encrypt(*ctxt_one, *ptxt_tmp, pri_key);
        ppfim::SecureSubsetTesting(*ctxt_result, ctxt_query, ctxt_trans, *ctxt_one, 
                length, stream, stream_num);
        cufhe::Decrypt(*result_decrypted, *ctxt_result, pri_key);

        // Somewhat secure model
        ppfim::SomewhatSecureSubsetTesting(*ctxt_somewhat_result, query, ctxt_trans, *ctxt_one, 
                length, stream, stream_num);
        cufhe::Decrypt(*result_somewhat_decrypted, *ctxt_somewhat_result, pri_key);

        correct_secure &= (result_decrypted->message_ 
                       == ptxt_result->message_);
        correct_somewhat &= (result_somewhat_decrypted->message_ 
                         == ptxt_result->message_);

        delete[] query;
        delete[] trans;
        delete[] ctxt_query;
        delete[] ctxt_trans;
        delete ptxt_tmp;
        delete ptxt_result;
        delete ctxt_result;
        delete ctxt_somewhat_result;
        delete ctxt_one;
        delete result_decrypted;
        delete result_somewhat_decrypted;
    }

    correct = correct_secure & correct_somewhat;
    std::cout << (correct ? "PASS" : "FAIL") << std::endl;

}


void TestSecureCompare(const cufhe::PubKey &pub_key,
                             const cufhe::PriKey &pri_key,
                             cufhe::Stream* stream,
                             uint32_t stream_num) {
    int test_times = 20;
    std::cout << "Test (fast) secure subset testing algorithm " << test_times << " times...\n";
    bool correct = true;
    uint32_t length = 30;
    int num1, num2;
    for (int i = 0; i < test_times; ++i) {
        num1 = rand() % 100000 + 1;
        num2 = rand() % 100000 + 1;

        // Generate an equivment testcase
        if (num1 % 10 == 0)
            num1 = num2;

        cufhe::Ptxt *ptxt_num1 = new cufhe::Ptxt[length];
        cufhe::Ptxt *ptxt_num2 = new cufhe::Ptxt[length];
        cufhe::Ptxt *result_decrypted = new cufhe::Ptxt;
        cufhe::Ptxt *ptxt_zero = new cufhe::Ptxt;
        cufhe::Ptxt *ptxt_one = new cufhe::Ptxt;

        cufhe::Ctxt *ctxt_num1 = new cufhe::Ctxt[length];
        cufhe::Ctxt *ctxt_num2 = new cufhe::Ctxt[length];
        cufhe::Ctxt *ctxt_result = new cufhe::Ctxt;
        cufhe::Ctxt *ctxt_zero = new cufhe::Ctxt;
        cufhe::Ctxt *ctxt_one = new cufhe::Ctxt;

        ppfim::DecToBin(ptxt_num1, num1, length);
        ppfim::DecToBin(ptxt_num2, num2, length);
        
        for (int j = 0; j < length; ++j) {
            cufhe::Encrypt(ctxt_num1[j], ptxt_num1[j], pri_key);
            cufhe::Encrypt(ctxt_num2[j], ptxt_num2[j], pri_key);
        }

        ptxt_zero->message_ = 0;
        cufhe::Encrypt(*ctxt_zero, *ptxt_zero, pri_key);
        ptxt_one->message_ = 1;
        cufhe::Encrypt(*ctxt_one, *ptxt_one, pri_key);
       
        ppfim::FastSecureCompare(*ctxt_result, ctxt_num1, ctxt_num2, 
                *ctxt_zero, *ctxt_one, length, stream, stream_num);//, pri_key); 


        cufhe::Decrypt(*result_decrypted, *ctxt_result, pri_key);

        correct &= (result_decrypted->message_ == (num1 < num2));

        delete[] ptxt_num1;
        delete[] ptxt_num2;
        delete[] ctxt_num1;
        delete[] ctxt_num2;
        delete ctxt_result;
        delete ctxt_zero;
        delete ptxt_zero;
        delete ctxt_one;
        delete ptxt_one;
        delete result_decrypted;
    }

    std::cout << (correct ? "PASS" : "FAIL") << std::endl;

}


void TestSecureCount(const cufhe::PubKey &pub_key,
                             const cufhe::PriKey &pri_key,
                             cufhe::Stream* stream,
                             uint32_t stream_num) {
    int test_times = 20;
    std::cout << "Test secure count algorithm " << test_times << " times...\n";
    bool correct = true;
    uint32_t length;
    for (int i = 0; i < test_times; ++i) {

        length = rand() % 20 + 10;
        int num_counter = rand() % 1000 + 1;
        int num_bit = rand() % 2;

        cufhe::Ptxt *ptxt_counter = new cufhe::Ptxt[length];
        cufhe::Ptxt *ptxt_bit = new cufhe::Ptxt;

        cufhe::Ctxt *ctxt_counter = new cufhe::Ctxt[length];
        cufhe::Ctxt *ctxt_bit = new cufhe::Ctxt;

        ppfim::DecToBin(ptxt_counter, num_counter, length);
        for (int j = 0; j < length; ++ j) {
            cufhe::Encrypt(ctxt_counter[j], ptxt_counter[j], pri_key);
        }
        
        ptxt_bit->message_ = num_bit;
        cufhe::Encrypt(*ctxt_bit, *ptxt_bit, pri_key);

        ppfim::SecureCount(ctxt_counter, *ctxt_bit, length, stream, stream_num);
        
        for (int j = 0; j < length; ++ j) {
            cufhe::Decrypt(ptxt_counter[j], ctxt_counter[j], pri_key);
        }

        int decrypted_num_counter = ppfim::BinToDec(ptxt_counter, length);
        
        correct &= (decrypted_num_counter == (num_counter + num_bit));

        delete[] ptxt_counter;
        delete[] ctxt_counter;
        delete ptxt_bit;
        delete ctxt_bit;
    }

    std::cout << (correct ? "PASS" : "FAIL") << std::endl;
}

 
void TestFreqItemsetMining(const cufhe::PubKey &pub_key,
                             const cufhe::PriKey &pri_key,
                             cufhe::Stream* stream,
                             uint32_t stream_num) {
    int test_times = 20;//20;
    std::cout << "Test freq itemset mining protocols " << test_times << " times...\n";
    bool correct = true, correct_first = true, correct_second = true;
    uint32_t rows, cols, counter_length, min_supp_count;
    double min_supp;
    
    for (int i = 0; i < test_times; ++i) {

        rows = rand() % 10 + 5;
        cols = rand() % 10 + 5;
        counter_length = floor(log2((double)rows)) + 1;
        min_supp = (rand() % 10) / 10.0;
        min_supp_count = (int)(min_supp * rows);

        // Generate plaintext matrix
        std::vector<cufhe::Ptxt *> ptxt_data_matrix(rows);
        for (int j = 0; j < rows; ++ j) {
            ptxt_data_matrix[j] = new cufhe::Ptxt[cols];
            for (int k = 0; k < cols; ++ k) {
                ptxt_data_matrix[j][k].message_ = rand() % cufhe::Ptxt::kPtxtSpace;
            }
        }

        // Generate plaintext query
        cufhe::Ptxt *ptxt_query = new cufhe::Ptxt[cols];
        for (int j = 0; j < cols; ++ j) {
            int tmp = rand();
            ptxt_query[j].message_ = (tmp % 5 == 0? 1 : 0); // Let "1"s be sparse
        }

        // Generate plaintext min supp count
        cufhe::Ptxt *ptxt_min_supp_count = new cufhe::Ptxt[counter_length];
        ppfim::DecToBin(ptxt_min_supp_count, min_supp_count, counter_length);

        // Generate ciphertext matrix
        std::vector<cufhe::Ctxt *> ctxt_data_matrix(rows);
        for (int j = 0; j < rows; ++j) {
            ctxt_data_matrix[j] = new cufhe::Ctxt[cols];
            for (int k = 0; k < cols; ++ k) {
                cufhe::Encrypt(ctxt_data_matrix[j][k], ptxt_data_matrix[j][k], pri_key);
            }
        }

        // Generate ciphertext query
        cufhe::Ctxt *ctxt_query = new cufhe::Ctxt[cols];
        for (int j = 0; j < cols; ++ j) {
            cufhe::Encrypt(ctxt_query[j], ptxt_query[j], pri_key);
        }

        // Generate ciphertext min supp count
        cufhe::Ctxt *ctxt_min_supp_count = new cufhe::Ctxt[counter_length];
        for (int j = 0; j < counter_length; ++ j) {
            cufhe::Encrypt(ctxt_min_supp_count[j], ptxt_min_supp_count[j], pri_key);
        }


        // Generate plaintext and ciphertext "1" and "0"
        cufhe::Ctxt *ctxt_one = new cufhe::Ctxt;
        cufhe::Ctxt *ctxt_zero = new cufhe::Ctxt;
        cufhe::Ptxt *ptxt_one = new cufhe::Ptxt;
        cufhe::Ptxt *ptxt_zero = new cufhe::Ptxt;
        ptxt_one->message_ = 1;
        ptxt_zero->message_ = 0;
        cufhe::Encrypt(*ctxt_one, *ptxt_one, pri_key);
        cufhe::Encrypt(*ctxt_zero, *ptxt_zero, pri_key);

        // Generate plaintext and ciphertext mining result
        cufhe::Ctxt *ctxt_mining_result_first = new cufhe::Ctxt;
        cufhe::Ctxt *ctxt_mining_result_second = new cufhe::Ctxt;
        cufhe::Ptxt *decrypted_mining_result_first = new cufhe::Ptxt;
        cufhe::Ptxt *decrypted_mining_result_second = new cufhe::Ptxt;
        cufhe::Ptxt *trivial_mining_result = new cufhe::Ptxt;

        // Running protocol 1 & 2
        //time_t time_start = time(0);
        ppfim::FreqItemsetMiningFirst(*ctxt_mining_result_first,
                                      ctxt_data_matrix,
                                      rows,
                                      cols,
                                      ctxt_min_supp_count,
                                      ctxt_query,
                                      counter_length,
                                      *ctxt_zero,
                                      *ctxt_one,
                                      stream,
                                      stream_num);
        
        //time_t time_finish = time(0);
        //std::cout << time_finish - time_start << std::endl;

        //time_start = time(0);
        ppfim::FreqItemsetMiningSecond(*ctxt_mining_result_second,
                                       ctxt_data_matrix,
                                       rows,
                                       cols,
                                       ctxt_min_supp_count,
                                       ptxt_query,
                                       counter_length,
                                       *ctxt_zero,
                                       *ctxt_one,
                                       stream,
                                       stream_num);
        //time_finish = time(0);
        //std::cout << time_finish - time_start << std::endl;

        TrivialFreqItemsetMining(*trivial_mining_result,
                                 ptxt_data_matrix,
                                 rows,
                                 cols,
                                 ptxt_query,
                                 min_supp_count);

        // Decrypt mining results
        cufhe::Decrypt(*decrypted_mining_result_first,
                       *ctxt_mining_result_first,
                       pri_key);
        cufhe::Decrypt(*decrypted_mining_result_second,
                       *ctxt_mining_result_second,
                       pri_key);

        int first = decrypted_mining_result_first->message_;
        int second = decrypted_mining_result_second->message_;
        int trivial = trivial_mining_result->message_;

        //std::cout <<   "first result:"  << first 
        //          << ", second result:" << second 
        //          << ", trivial result:"<< trivial << std::endl;
        
        correct_first &= (first == trivial);
        correct_second &= (second == trivial);

        // Clean up
        for (int j = 0; j < rows; ++ j) {
            delete [] (ptxt_data_matrix[j]);
        }
        delete [] ptxt_query;
        delete [] ptxt_min_supp_count;
        for (int j = 0; j < rows; ++ j) {
            delete [] (ctxt_data_matrix[j]);
        }
        delete [] ctxt_query;
        delete [] ctxt_min_supp_count;

        delete ctxt_one;
        delete ctxt_zero;
        delete ptxt_one;
        delete ptxt_zero;

        delete ctxt_mining_result_first;
        delete ctxt_mining_result_second;
        delete decrypted_mining_result_first;
        delete decrypted_mining_result_second;
        delete trivial_mining_result;
    }

    correct = correct_first & correct_second;
    std::cout << (correct ? "PASS" : "FAIL") << std::endl;
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
    TestSecureSubsetTesting(pub_key, pri_key, stream, kNumSMs);
    TestSecureCompare(pub_key, pri_key, stream, kNumSMs);
    TestSecureCount(pub_key, pri_key, stream, kNumSMs);
    TestFreqItemsetMining(pub_key, pri_key,  stream, kNumSMs);

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
