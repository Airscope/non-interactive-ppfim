//
// Created by z1y on 2019/9/25.
//

//
// Created by z1y on 2019/9/25.
//

#include <iostream>
#include <tfhe/tfhe.h>

#include "user.h"

void print(const std::vector<int> &vec) {
    for (auto i : vec) {
        std::cout << i << " ";
    }
    std::cout << std::endl;
}

void print(const std::vector<std::vector<int>> &mat) {
    for (const auto &i : mat)
        print(i);
}

void test_load_data() {
    std::cout << "Test function load_data(), loading a 10*10 boolean matrix..." << std::endl;
    print(ppfim::load_data("../dataset_chess.txt", 10, 10));
    std::cout << "PASS" << std::endl;
}

void
test_ctxt_min_supp_count(TFheGateBootstrappingSecretKeySet *secret_key, TFheGateBootstrappingParameterSet *params) {
    srand(time(nullptr));
    int test_times = 10, length = 0, rows = 1000;
    double min_supp;
    std::vector<int> decrypted_bits;
    bool test_result_now = true;

    std::cout << "Test functon ctxt_min_supp_count() " << test_times << " times...\n";
    for (int i = 0; i < test_times; ++i) {
        length = rand() % 10 + 10; // [10, 19]
        min_supp = (rand() % 100) / 100.0; // [0.00 0.99]

        decrypted_bits.resize(length);

        LweSample *ctxt_min_supp = new_gate_bootstrapping_ciphertext_array(length, params);
        ppfim::ctxt_min_supp_count(ctxt_min_supp, length, int(min_supp * rows), secret_key);

        for (int j = 0; j < length; ++j) {
            decrypted_bits[j] = bootsSymDecrypt(&ctxt_min_supp[j], secret_key);
        }
        // print(decrypted_bits);
        // print(ptxt_query);
        test_result_now &= (ppfim::bin_to_dec(decrypted_bits) == int(min_supp * rows));
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_min_supp);
    }
    std::cout << (test_result_now ? "PASS" : "FAIL") << std::endl;
}

void test_encrypt_decrypt(TFheGateBootstrappingSecretKeySet *secret_key,
                          TFheGateBootstrappingParameterSet *params) {
    std::cout << "Test decryption and encryption ...\n";
    int m = 10, n = 10;
    auto ptxt_matrix = ppfim::load_data("../dataset_chess.txt", m, n);
    std::vector<LweSample *> ctxt_matrix(m);
    for (int i = 0; i < m; ++i) {
        ctxt_matrix[i] = new_gate_bootstrapping_ciphertext_array(n, params);
    }

    ppfim::encrypt_data(ctxt_matrix, m, n, ptxt_matrix, secret_key);

    auto decrypted_data_matrix = ppfim::decrypt_data(ctxt_matrix, m, n, secret_key);
    // print(ptxt_matrix);
    // std::cout << std::endl;
    // print(decrypted_data_matrix);
    std::cout << (ptxt_matrix == decrypted_data_matrix ? "PASS" : "FAIL") << std::endl;

    // Clear
    for (int j = 0; j < m; ++j) {
        delete_gate_bootstrapping_ciphertext_array(n, ctxt_matrix[j]);
    }
}

void test_all() {
    //generate a keyset
    const int32_t minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *secret_key = new_random_gate_bootstrapping_secret_keyset(params);

    // test all
    test_load_data();
    test_ctxt_min_supp_count(secret_key, params);
    test_encrypt_decrypt(secret_key, params);
}


int main() {
    test_all();
    return 0;
}