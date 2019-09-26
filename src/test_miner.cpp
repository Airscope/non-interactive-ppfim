//
// Created by z1y on 2019/9/25.
//

#include <iostream>
#include <tfhe/tfhe.h>

#include "miner.h"

void print(const std::vector<int> &vec) {
    for (auto i : vec) {
        std::cout << i << " ";
    }
    std::cout << std::endl;
}

int main() {
    //generate a keyset
    const int32_t minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *secret_key = new_random_gate_bootstrapping_secret_keyset(params);

    srand(time(nullptr));
    int test_times = 10, length = 0;
    std::vector<int> decrypted_bits;
    bool test_result_now = true;

    std::cout << "Test miner.cpp " << test_times << " times...\n";
    for (int i = 0; i < test_times; ++i) {
        length = rand() % 100 + 1;
        decrypted_bits.resize(length);
        auto ptxt_query = ppfim::plaintext_query(length);
        LweSample *ctxt_query = new_gate_bootstrapping_ciphertext_array(length, params);
        ppfim::ciphertext_query(ctxt_query, length, secret_key);
        for (int j = 0; j < length; ++j) {
            decrypted_bits[j] = bootsSymDecrypt(&ctxt_query[j], secret_key);
        }
        // print(decrypted_bits);
        // print(ptxt_query);
        test_result_now &= (decrypted_bits == ptxt_query);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_query);
    }
    std::cout << (test_result_now ? "PASS" : "FAIL") << std::endl;
    return 0;
}