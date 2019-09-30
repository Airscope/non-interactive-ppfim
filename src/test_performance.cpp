//
// Created by z1y on 2019/9/26.
//

#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <chrono>

#include "cloud.h"
#include "user.h"
#include "miner.h"

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
    std::cout << "] milliseconds. Average time: " << total_times / (double) times.size() << " milliseconds.\n";
}

int main() {

    // Generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    // Generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *secret_key = new_random_gate_bootstrapping_secret_keyset(params);

    // Generate a cloud key
    const TFheGateBootstrappingCloudKeySet *cloud_key = &secret_key->cloud;

    std::string file_name = "../dataset_chess.txt";
    const double min_supp = 0.8;
    int test_times = 5; // Test each protocol 5 times

    std::vector<int> trans_num = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000};
    std::vector<int> items_num = {10, 20, 30, 40, 50, 60, 70};

    for (auto m : trans_num) {

        int n = 20;
        int k = floor(log2(m)) + 1;

        std::cout << "Trans Number: " << m << ", Items Number: " << n << std::endl;

        // Load data matrix from disk
        auto data_matrix = ppfim::load_data(file_name, m, n);

        // Encrypt data matrix
        std::vector<LweSample *> ctxt_data_matrix(m);
        for (int i = 0; i < m; ++i) {
            ctxt_data_matrix[i] = new_gate_bootstrapping_ciphertext_array(n, cloud_key->params);
        }
        ppfim::encrypt_data(ctxt_data_matrix, m, n, data_matrix, secret_key);

        // Get a ciphertext minimum support count
        LweSample *ctxt_min_supp_count = new_gate_bootstrapping_ciphertext_array(k, cloud_key->params);
        ppfim::ctxt_min_supp_count(ctxt_min_supp_count, k, static_cast<int>(m * min_supp), secret_key);

        // Get the ciphertext and the plaintext query
        auto ptxt_query = ppfim::plaintext_query(n);
        LweSample *ctxt_query = new_gate_bootstrapping_ciphertext_array(n, cloud_key->params);
        ppfim::ciphertext_query(ctxt_query, n, secret_key);

        // Allocate memory for the mining result;
        LweSample *mining_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        std::chrono::high_resolution_clock::time_point time_start, time_finish;
        std::vector<std::chrono::milliseconds> time_diffs_p1;
        std::vector<std::chrono::milliseconds> time_diffs_p2;

        for (int j = 0; j < test_times; ++j) {

            // Test protocol 1's performance
            time_start = std::chrono::high_resolution_clock::now();
            ppfim::freq_itemset_mining_first(mining_result, ctxt_data_matrix, m, n, ctxt_query, ctxt_min_supp_count,
                                             cloud_key);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p1.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));

            // Test protocol 2's performance
            time_start = std::chrono::high_resolution_clock::now();
            ppfim::freq_itemset_mining_second(mining_result, ctxt_data_matrix, m, n, ptxt_query, ctxt_min_supp_count,
                                              cloud_key);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p2.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));
        }

        // Print info
        std::cout << "Protocol 1 time used: ";
        print(time_diffs_p1);

        std::cout << "Protocol 2 time used: ";
        print(time_diffs_p2);

        // Clean up all pointers
        for (int i = 0; i < m; ++i) {
            delete_gate_bootstrapping_ciphertext_array(n, ctxt_data_matrix[i]);
        }
        delete_gate_bootstrapping_ciphertext_array(k, ctxt_min_supp_count);
        delete_gate_bootstrapping_ciphertext_array(n, ctxt_query);
        delete_gate_bootstrapping_ciphertext(mining_result);
    }


    for (auto n : items_num) {

        int m = 1000;
        int k = floor(log2(m)) + 1;

        std::cout << "Trans Number: " << m << ", Items Number: " << n << std::endl;

        // Load data matrix from disk
        auto data_matrix = ppfim::load_data(file_name, m, n);

        // Encrypt data matrix
        std::vector<LweSample *> ctxt_data_matrix(m);
        for (int i = 0; i < m; ++i) {
            ctxt_data_matrix[i] = new_gate_bootstrapping_ciphertext_array(n, cloud_key->params);
        }
        ppfim::encrypt_data(ctxt_data_matrix, m, n, data_matrix, secret_key);

        // Get a ciphertext minimum support count
        LweSample *ctxt_min_supp_count = new_gate_bootstrapping_ciphertext_array(k, cloud_key->params);
        ppfim::ctxt_min_supp_count(ctxt_min_supp_count, k, static_cast<int>(m * min_supp), secret_key);

        // Get the ciphertext and the plaintext query
        auto ptxt_query = ppfim::plaintext_query(n);
        LweSample *ctxt_query = new_gate_bootstrapping_ciphertext_array(n, cloud_key->params);
        ppfim::ciphertext_query(ctxt_query, n, secret_key);

        // Allocate memory for the mining result;
        LweSample *mining_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        std::chrono::high_resolution_clock::time_point time_start, time_finish;
        std::vector<std::chrono::milliseconds> time_diffs_p1;
        std::vector<std::chrono::milliseconds> time_diffs_p2;

        for (int j = 0; j < test_times; ++j) {

            // Test protocol 1's performance
            time_start = std::chrono::high_resolution_clock::now();
            ppfim::freq_itemset_mining_first(mining_result, ctxt_data_matrix, m, n, ctxt_query, ctxt_min_supp_count,
                                             cloud_key);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p1.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));

            // Test protocol 2's performance
            time_start = std::chrono::high_resolution_clock::now();
            ppfim::freq_itemset_mining_second(mining_result, ctxt_data_matrix, m, n, ptxt_query, ctxt_min_supp_count,
                                              cloud_key);
            time_finish = std::chrono::high_resolution_clock::now();
            time_diffs_p2.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(time_finish - time_start));
        }

        // Print info
        std::cout << "Protocol 1 time used: ";
        print(time_diffs_p1);

        std::cout << "Protocol 2 time used: ";
        print(time_diffs_p2);

        // Clean up all pointers
        for (int i = 0; i < m; ++i) {
            delete_gate_bootstrapping_ciphertext_array(n, ctxt_data_matrix[i]);
        }
        delete_gate_bootstrapping_ciphertext_array(k, ctxt_min_supp_count);
        delete_gate_bootstrapping_ciphertext_array(n, ctxt_query);
        delete_gate_bootstrapping_ciphertext(mining_result);
    }
    return 0;
}
