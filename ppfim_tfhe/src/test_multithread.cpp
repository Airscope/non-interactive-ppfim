//
// Created by z1y on 2019/10/1.
//

//
// Created by z1y on 2019/9/25.
//
#include <iostream>
#include <vector>
#include <cmath>
#include <cassert>

#include "multithread.h"
#include "user.h"
#include "cloud.h"
#include <thread>


template<typename T>
void print(const std::vector<T> &vec) {
    std::cout << "[";
    for (auto i : vec) {
        std::cout << i << " ";
    }
    std::cout << "]";
    std::cout << std::endl;
}

void print(const LweSample *ctxts, int length, const TFheGateBootstrappingSecretKeySet *secret_key) {
    std::vector<int> vec(length);
    for (int i = 0; i < length; ++i) {
        if (length != 1)
            vec[i] = bootsSymDecrypt(&ctxts[i], secret_key);
        else
            vec[i] = bootsSymDecrypt(ctxts, secret_key);
    }
    print<int>(vec);
}


bool trivial_subset_testing(const std::vector<bool> &query,
                            const std::vector<bool> &trans) {
    assert(query.size() == trans.size());
    bool ret = true;
    for (size_t i = 0; i < query.size(); ++i) {
        ret = ret and ((not query[i]) or trans[i]);
    }
    return ret;
}

void trivial_count(std::vector<bool> &counter, bool bit) {
    bool carry = bit, tmp;
    for (int i = counter.size() - 1; i >= 0; --i) {
        tmp = counter[i];
        counter[i] = (not(counter[i]) and carry) or (not(carry) and counter[i]);
        carry = carry and tmp;
    }
}

bool trivial_freq_itemset_mining(const std::vector<std::vector<bool>> &data_matrix,
                                 const std::vector<bool> &query,
                                 const int min_supp_count) {
    int m = data_matrix.size();
    int counter_size = floor(log2(m)) + 1;
    bool subset_test_result;
    std::vector<bool> counter(counter_size, false);
    for (int i = 0; i < m; ++i) {
        subset_test_result = trivial_subset_testing(query, data_matrix[i]);
        trivial_count(counter, subset_test_result);
    }
    std::vector<int> res(counter_size, 0);
    for (int i = 0; i < counter_size; ++i)
        res[i] = (counter[i] ? 1 : 0);

    int a = ppfim::bin_to_dec(res);
    return a < min_supp_count;
}


void test_parallel_freq_itemset_mining(const TFheGateBootstrappingSecretKeySet *secret_key,
                                       const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 10;
    std::cout << "Test parallel freq itemset mining protocol " << test_times << " times...\n";
    bool test_result = true;
    int thread_num = 4;
    for (int i = 0; i < test_times; ++i) {

        int rows = rand() % 20 + 20;
        int cols = rand() % 5 + 10;
        int counter_size = floor(log2(rows)) + 1;

        // Generate a random bool matrix
        std::vector<std::vector<int>> data_matrix(rows, std::vector<int>(cols));
        std::vector<std::vector<bool>> data_matrix_bool(rows, std::vector<bool>(cols));

        for (int j = 0; j < rows; ++j) {
            for (int k = 0; k < cols; ++k) {
                data_matrix_bool[j][k] = ((data_matrix[j][k] = rand() % 2) == 1);
            }
        }

        // Allocate memory and init for ctxt_data_matrix
        std::vector<LweSample *> ctxt_data_matrix(rows);
        for (int j = 0; j < rows; ++j) {
            ctxt_data_matrix[j] = new_gate_bootstrapping_ciphertext_array(cols, cloud_key->params);
        }
        ppfim::encrypt_data(ctxt_data_matrix, rows, cols, data_matrix, secret_key);

        // Generate min_supp(_count) ...
        double min_supp = (rand() % 100) / 100.0;
        int min_supp_count = min_supp * rows;
        auto bin_min_supp_count = ppfim::dec_to_bin(min_supp_count, counter_size);

        // Allocate memory and init for ctxt_min_supp_count
        LweSample *ctxt_min_supp_count = new_gate_bootstrapping_ciphertext_array(counter_size, cloud_key->params);
        for (int j = 0; j < counter_size; ++j) {
            bootsSymEncrypt(&ctxt_min_supp_count[j], bin_min_supp_count[j], secret_key);
        }

        // Generate query
        std::vector<int> query(cols);
        std::vector<bool> query_bool;
        for (auto &q : query) {
            q = (rand() % 5 == 0 ? 1 : 0);
            query_bool.push_back(q == 1);
        }

        // Allocate memory and init for ctxt_query
        LweSample *ctxt_query = new_gate_bootstrapping_ciphertext_array(cols, cloud_key->params);
        for (int j = 0; j < cols; ++j) {
            bootsSymEncrypt(&ctxt_query[j], query[j], secret_key);
        }

        // Allocate memory for results
        LweSample *ctxt_protocol1_result = new_gate_bootstrapping_ciphertext(cloud_key->params);
        LweSample *ctxt_protocol2_result = new_gate_bootstrapping_ciphertext(cloud_key->params);


        // Run protocols
        ppfim::parallel_freq_itemset_mining_first(ctxt_protocol1_result, thread_num, ctxt_data_matrix, rows, cols,
                                                  ctxt_query, ctxt_min_supp_count, counter_size, cloud_key);
        ppfim::parallel_freq_itemset_mining_second(ctxt_protocol2_result, thread_num, ctxt_data_matrix, rows, cols,
                                                   query, ctxt_min_supp_count, counter_size, cloud_key);
        int trivial_result = trivial_freq_itemset_mining(data_matrix_bool, query_bool, min_supp_count);

        // Decryption
        int ptxt_protocol1_result = bootsSymDecrypt(ctxt_protocol1_result, secret_key);
        int ptxt_protocol2_result = bootsSymDecrypt(ctxt_protocol2_result, secret_key);

        //std::cout << "First: " << ptxt_protocol1_result
        //          << ", Second: " << ptxt_protocol2_result
        //          << ", Trivial: " << trivial_result << std::endl;

        // Update test flag
        test_result &= ((trivial_result == ptxt_protocol1_result) && (ptxt_protocol1_result == ptxt_protocol2_result));

        // Clear
        for (int l = 0; l < rows; ++l) {
            delete_gate_bootstrapping_ciphertext_array(cols, ctxt_data_matrix[l]);
        }
        delete_gate_bootstrapping_ciphertext_array(counter_size, ctxt_min_supp_count);
        delete_gate_bootstrapping_ciphertext_array(cols, ctxt_query);
        delete_gate_bootstrapping_ciphertext(ctxt_protocol1_result);
        delete_gate_bootstrapping_ciphertext(ctxt_protocol2_result);
    }

    std::cout << (test_result ? "PASS" : "FAIL") << std::endl;
}

void test_all() {

    srand(time(nullptr));

    //generate a keyset
    const int32_t minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *secret_key = new_random_gate_bootstrapping_secret_keyset(params);

    // test all
    test_parallel_freq_itemset_mining(secret_key, &(secret_key->cloud));
}

int main() {
    test_all();
    return 0;
}
