//
// Created by z1y on 2019/9/25.
//
#include <iostream>
#include <vector>
#include <cmath>
#include <cassert>

#include "cloud.h"
#include "user.h"

template<typename T>
void print(const std::vector<T> &vec) {
    for (auto i : vec) {
        std::cout << i << " ";
    }
}

void print(const LweSample *ctxts, int length, const TFheGateBootstrappingSecretKeySet *secret_key) {
    std::vector<int> vec(length);
    for (int i = 0; i < length; ++i) {
        if (length != 1)
            vec[i] = bootsSymDecrypt(&ctxts[i], secret_key);
        else
            vec[i] = bootsSymDecrypt(ctxts, secret_key);
    }
    std::cout << "[";
    print<int>(vec);
    std::cout << "]";
    std::cout << std::endl;
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

    return ppfim::bin_to_dec(res) < min_supp_count;
}


void test_secure_subset_testing(const TFheGateBootstrappingSecretKeySet *secret_key,
                                const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 20;
    std::cout << "Test secure subset testing algorithm " << test_times << " times...\n";
    bool test_result = true;
    int length = 0;
    for (int i = 0; i < test_times; ++i) {
        length = rand() % 20 + 1;
        std::vector<int> query(length);
        std::vector<bool> query_bool;
        for (auto &qq : query) {
            qq = rand() % 2;
            query_bool.push_back(qq == 1);
        }

        std::vector<int> trans(length);
        std::vector<bool> trans_bool;
        for (auto &tt : trans) {
            tt = rand() % 2;
            trans_bool.push_back(tt == 1);
        }

        LweSample *ctxt_query = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *ctxt_trans = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *secure_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        for (int j = 0; j < length; ++j) {
            bootsSymEncrypt(&ctxt_query[j], query[j], secret_key);
        }
        for (int j = 0; j < length; ++j) {
            bootsSymEncrypt(&ctxt_trans[j], trans[j], secret_key);
        }
        int trivial_result = trivial_subset_testing(query_bool, trans_bool) ? 1 : 0;
        ppfim::secure_subset_testing(secure_result, ctxt_query, ctxt_trans, length, cloud_key);

        int decrypted_result = bootsSymDecrypt(secure_result, secret_key);
        test_result = test_result and (decrypted_result == trivial_result);

        delete_gate_bootstrapping_ciphertext(secure_result);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_query);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_trans);
    }

    std::cout << (test_result ? "PASS" : "FAIL") << std::endl;
}

void test_somewhat_secure_subset_testing(const TFheGateBootstrappingSecretKeySet *secret_key,
                                         const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 20;
    std::cout << "Test somewhat secure subset testing algorithm " << test_times << " times...\n";
    bool test_result = true;
    int length = 0;
    for (int i = 0; i < test_times; ++i) {
        length = rand() % 20 + 1;
        std::vector<int> query(length);
        std::vector<bool> query_bool;
        for (auto &qq : query) {
            qq = rand() % 2;
            query_bool.push_back(qq == 1);
        }

        std::vector<int> trans(length);
        std::vector<bool> trans_bool;
        for (auto &tt : trans) {
            tt = rand() % 2;
            trans_bool.push_back(tt == 1);
        }

        LweSample *ctxt_trans = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *secure_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        for (int j = 0; j < length; ++j) {
            bootsSymEncrypt(&ctxt_trans[j], trans[j], secret_key);
        }

        int trivial_result = trivial_subset_testing(query_bool, trans_bool);
        ppfim::somewhat_secure_subset_testing(secure_result, query, ctxt_trans, length, cloud_key);

        int decrypted_result = bootsSymDecrypt(secure_result, secret_key);
        test_result = test_result and (decrypted_result == trivial_result);

        delete_gate_bootstrapping_ciphertext(secure_result);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_trans);
    }

    std::cout << (test_result ? "PASS" : "FAIL") << std::endl;
}

void test_secure_count(const TFheGateBootstrappingSecretKeySet *secret_key,
                       const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 20;
    std::cout << "Test secure count algorithm " << test_times << " times...\n";
    bool test_result = true;
    int length = 0;
    for (int i = 0; i < test_times; ++i) {
        length = rand() % 20 + 1;
        std::vector<int> counter(length, 0);
        std::vector<bool> counter_bool(length, false);
        int bit = rand() % 2;

        LweSample *ctxt_counter = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *ctxt_bit = new_gate_bootstrapping_ciphertext(cloud_key->params);

        for (int j = 0; j < length; ++j) {
            bootsSymEncrypt(&ctxt_counter[j], counter[j], secret_key);
        }
        bootsSymEncrypt(ctxt_bit, bit, secret_key);

        ppfim::secure_count(ctxt_counter, length, ctxt_bit, cloud_key);
        trivial_count(counter_bool, bit);

        for (int l = 0; l < length; ++l) {
            counter[l] = (counter_bool[l] ? 1 : 0);
        }

        std::vector<int> decrypted_result(length);
        for (int k = 0; k < length; ++k) {
            decrypted_result[k] = bootsSymDecrypt(&ctxt_counter[k], secret_key);
        }

        test_result = test_result and (decrypted_result == counter);

        delete_gate_bootstrapping_ciphertext(ctxt_bit);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_counter);
    }

    std::cout << (test_result ? "PASS" : "FAIL") << std::endl;
}

void test_secure_compare(const TFheGateBootstrappingSecretKeySet *secret_key,
                         const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 20;
    std::cout << "Test secure compare algorithm " << test_times << " times...\n";
    bool test_result = true;
    int length = 20;
    for (int i = 0; i < test_times; ++i) {
        int dec_num1 = rand() % 100000 + 1;
        int dec_num2 = rand() % 100000 + 1;
        auto bin_num1 = ppfim::dec_to_bin(dec_num1, length);
        auto bin_num2 = ppfim::dec_to_bin(dec_num2, length);

        LweSample *ctxt_num1 = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *ctxt_num2 = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *cmp_result = new_gate_bootstrapping_ciphertext(cloud_key->params);
        LweSample *fast_cmp_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        for (int j = 0; j < length; ++j) {
            bootsSymEncrypt(&ctxt_num1[j], bin_num1[j], secret_key);
            bootsSymEncrypt(&ctxt_num2[j], bin_num2[j], secret_key);
        }

        //time_t time_start = time(0);
        ppfim::secure_compare(cmp_result, ctxt_num1, ctxt_num2, length, cloud_key);
        //time_t time_finish = time(0);
        //std::cout << "secure compare time:" << time_finish - time_start << std::endl;

        //time_start = time(0);
        ppfim::fast_secure_compare(fast_cmp_result, ctxt_num1, ctxt_num2, length, cloud_key);
        //time_finish = time(0);
        //std::cout << "fast secure compare time:" << time_finish - time_start << std::endl;

        int ptxt_cmp_result = bootsSymDecrypt(cmp_result, secret_key);
        int fast_ptxt_cmp_result = bootsSymDecrypt(fast_cmp_result, secret_key);

        //std::cout <<  dec_num1  << "<" << dec_num2 << "? " 
        //          << ptxt_cmp_result << ", " << fast_ptxt_cmp_result << std::endl; 

        test_result &= ((ptxt_cmp_result == (dec_num1 < dec_num2))
                        & (ptxt_cmp_result == fast_ptxt_cmp_result));

        delete_gate_bootstrapping_ciphertext(cmp_result);
        delete_gate_bootstrapping_ciphertext(fast_cmp_result);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_num1);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_num2);
    }

    std::cout << (test_result ? "PASS" : "FAIL") << std::endl;
}

void test_secure_add(const TFheGateBootstrappingSecretKeySet *secret_key,
                     const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 20;
    std::cout << "Test secure add algorithm " << test_times << " times...\n";
    bool test_result = true;
    int length = 20;
    for (int i = 0; i < test_times; ++i) {
        int dec_num1 = rand() % 100000 + 1;
        int dec_num2 = rand() % 100000 + 1;

        auto bin_num1 = ppfim::dec_to_bin(dec_num1, length);
        auto bin_num2 = ppfim::dec_to_bin(dec_num2, length);
        std::vector<int> decrypted(length);

        LweSample *ctxt_num1 = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *ctxt_num2 = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *ctxt_add = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);

        for (int j = 0; j < length; ++j) {
            bootsSymEncrypt(&ctxt_num1[j], bin_num1[j], secret_key);
            bootsSymEncrypt(&ctxt_num2[j], bin_num2[j], secret_key);
        }

        ppfim::secure_add(ctxt_add, ctxt_num1, ctxt_num2, length, cloud_key);
        for (int j = 0; j < length; ++j) {
            decrypted[j] = bootsSymDecrypt(&ctxt_add[j], secret_key);
        }
        int sum = ppfim::bin_to_dec(decrypted);

        std::cout << dec_num1 << " + " << dec_num2 << "? " << sum << std::endl;
        test_result &= (sum == dec_num1 + dec_num2);

        delete_gate_bootstrapping_ciphertext_array(length, ctxt_num1);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_num2);
        delete_gate_bootstrapping_ciphertext_array(length, ctxt_add);
    }

    std::cout << (test_result ? "PASS" : "FAIL") << std::endl;
}

void test_freq_itemset_mining(const TFheGateBootstrappingSecretKeySet *secret_key,
                              const TFheGateBootstrappingCloudKeySet *cloud_key) {
    int test_times = 20;
    std::cout << "Test freq itemset mining protocol " << test_times << " times...\n";
    bool test_result = true;
    for (int i = 0; i < test_times; ++i) {

        int rows = rand() % 10 + 1;
        int cols = rand() % 10 + 1;
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
            q = rand() % 2;
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
        ppfim::freq_itemset_mining_first(ctxt_protocol1_result,
                                         ctxt_data_matrix,
                                         rows,
                                         cols,
                                         ctxt_query,
                                         ctxt_min_supp_count,
                                         cloud_key);

        ppfim::freq_itemset_mining_second(ctxt_protocol2_result,
                                          ctxt_data_matrix,
                                          rows,
                                          cols,
                                          query,
                                          ctxt_min_supp_count,
                                          cloud_key);

        int trivial_result = trivial_freq_itemset_mining(data_matrix_bool, query_bool, min_supp_count);

        // Decryption
        int ptxt_protocol1_result = bootsSymDecrypt(ctxt_protocol1_result, secret_key);
        int ptxt_protocol2_result = bootsSymDecrypt(ctxt_protocol2_result, secret_key);

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
    test_secure_subset_testing(secret_key, &(secret_key->cloud));
    test_somewhat_secure_subset_testing(secret_key, &(secret_key->cloud));
    test_secure_count(secret_key, &(secret_key->cloud));
    test_secure_compare(secret_key, &(secret_key->cloud));
    test_secure_add(secret_key, &(secret_key->cloud));
    test_freq_itemset_mining(secret_key, &(secret_key->cloud));
}

int main() {
    test_all();
    return 0;
}
