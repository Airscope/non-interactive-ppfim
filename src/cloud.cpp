//
// Created by z1y on 2019/9/25.
//
#include <cassert>
#include <cmath>

#include "cloud.h"

namespace ppfim {

    void secure_subset_testing(LweSample *result,
                               const LweSample *ctxt_query,
                               const LweSample *ctxt_trans,
                               const int length,
                               const TFheGateBootstrappingCloudKeySet *cloud_key) {
        bootsCONSTANT(result, 1, cloud_key);
        LweSample *tmp = new_gate_bootstrapping_ciphertext(cloud_key->params);
        for (int i = 0; i < length; ++i) {
            bootsORNY(tmp, &ctxt_query[i], &ctxt_trans[i], cloud_key);
            bootsAND(result, result, tmp, cloud_key);
        }
        delete_gate_bootstrapping_ciphertext(tmp);
    }

    void somewhat_secure_subset_testing(LweSample *result,
                                        const std::vector<int> &ptxt_query,
                                        const LweSample *ctxt_trans,
                                        const int length,
                                        const TFheGateBootstrappingCloudKeySet *cloud_key) {

        bootsCONSTANT(result, 1, cloud_key);
        for (int i = 0; i < length; ++i) {
            if (ptxt_query[i] == 1) {
                bootsAND(result, result, &(ctxt_trans[i]), cloud_key);
            }
        }
    }

    // Ensure counter == [[0],[0], ..., [0]]
    void secure_count(LweSample *ctxt_counter,
                      const int length,
                      const LweSample *ctxt_bit,
                      const TFheGateBootstrappingCloudKeySet *cloud_key) {

        LweSample *carry = new_gate_bootstrapping_ciphertext(cloud_key->params);
        LweSample *tmp = new_gate_bootstrapping_ciphertext(cloud_key->params);

        bootsCOPY(carry, ctxt_bit, cloud_key);
        for (int i = length - 1; i >= 0; --i) {
            bootsCOPY(tmp, &ctxt_counter[i], cloud_key);
            bootsXOR(&ctxt_counter[i], &ctxt_counter[i], carry, cloud_key);
            bootsAND(carry, carry, tmp, cloud_key);
        }

        delete_gate_bootstrapping_ciphertext(carry);
        delete_gate_bootstrapping_ciphertext(tmp);
    }

    // Time complexity: O(length * length)
    void secure_compare(LweSample *result,
                        const LweSample *lhs,
                        const LweSample *rhs,
                        const int length,
                        const TFheGateBootstrappingCloudKeySet *cloud_key) {

        LweSample *tmp = new_gate_bootstrapping_ciphertext(cloud_key->params);
        LweSample *tmp2 = new_gate_bootstrapping_ciphertext(cloud_key->params);

        bootsANDNY(result, &lhs[0], &rhs[0], cloud_key);
        for (int i = 1; i < length; ++i) {
            bootsANDNY(tmp, &lhs[i], &rhs[i], cloud_key);
            for (int j = 0; j < i; ++j) {
                bootsXNOR(tmp2, &lhs[j], &rhs[j], cloud_key);
                bootsAND(tmp, tmp, tmp2, cloud_key);
            }
            bootsXOR(result, result, tmp, cloud_key);
        }

        delete_gate_bootstrapping_ciphertext(tmp);
        delete_gate_bootstrapping_ciphertext(tmp2);
    }

    // Time complexity: O(length)
    void fast_secure_compare(LweSample *result,
                             const LweSample *lhs,
                             const LweSample *rhs,
                             const int length,
                             const TFheGateBootstrappingCloudKeySet *cloud_key) {
        
        LweSample *aux = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *aux2 = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
        LweSample *tmp = new_gate_bootstrapping_ciphertext(cloud_key->params);
        LweSample *tmp2 = new_gate_bootstrapping_ciphertext(cloud_key->params);
        
        for (int i = length - 1; i >= 0; --i) {
            bootsXNOR(&aux[i], &lhs[i], &rhs[i], cloud_key);
        }
        bootsCOPY(tmp, &aux[0], cloud_key);
        bootsCONSTANT(&aux[0], 1, cloud_key);
        for (int i = 1; i < length; ++ i) {
            bootsCOPY(tmp2, &aux[i], cloud_key);
            bootsAND(&aux[i], &aux[i-1], tmp, cloud_key);
            bootsCOPY(tmp, tmp2, cloud_key);
        }
        for (int i = 0; i < length; ++i) {
            bootsANDNY(&aux2[i], &lhs[i], &rhs[i], cloud_key); // (not x) and y
            bootsAND(&aux2[i], &aux2[i], &aux[i], cloud_key);

            // Incorrect code, these make this function get lhs <= rhs
            // bootsORNY(&aux2[i], &lhs[i], &rhs[i], cloud_key); // (not x) or y
            // bootsORYN(&aux2[i], &aux2[i], &aux[i], cloud_key); // x or (not y)
        }
        
        // Incorrect also
        // bootsCONSTANT(result, 1, cloud_key);

        bootsCONSTANT(result, 0, cloud_key);

        for (int i = 0; i < length; ++i) {
            // Incorrect
            // bootsAND(result, result, &aux2[i], cloud_key);

            bootsOR(result, result, &aux2[i], cloud_key);
        }

        delete_gate_bootstrapping_ciphertext_array(length, aux);
        delete_gate_bootstrapping_ciphertext_array(length, aux2);
        delete_gate_bootstrapping_ciphertext(tmp);
        delete_gate_bootstrapping_ciphertext(tmp2);
    }


    void freq_itemset_mining_first(LweSample *result,
                                   const std::vector<LweSample *> &ctxt_data_matrix,
                                   const int rows,
                                   const int cols,
                                   const LweSample *ctxt_query,
                                   const LweSample *ctxt_min_supp_count,
                                   const TFheGateBootstrappingCloudKeySet *cloud_key) {

        const int counter_size = floor(log2(rows)) + 1;
        LweSample *ctxt_counter = new_gate_bootstrapping_ciphertext_array(counter_size, cloud_key->params);
        for (int i = 0; i < counter_size; ++i) {
            bootsCONSTANT(&ctxt_counter[i], 0, cloud_key);
        }

        LweSample *subset_test_result = new_gate_bootstrapping_ciphertext(cloud_key->params);
        for (int i = 0; i < rows; ++i) {
            secure_subset_testing(subset_test_result, ctxt_query, ctxt_data_matrix[i], cols, cloud_key);
            secure_count(ctxt_counter, counter_size, subset_test_result, cloud_key);
        }

        secure_compare(result, ctxt_counter, ctxt_min_supp_count, counter_size, cloud_key);

        delete_gate_bootstrapping_ciphertext_array(counter_size, ctxt_counter);
        delete_gate_bootstrapping_ciphertext(subset_test_result);
    }

    void freq_itemset_mining_second(LweSample *result,
                                    const std::vector<LweSample *> &ctxt_data_matrix,
                                    const int rows,
                                    const int cols,
                                    const std::vector<int> &ptxt_query,
                                    const LweSample *ctxt_min_supp_count,
                                    const TFheGateBootstrappingCloudKeySet *cloud_key) {

        const int counter_size = floor(log2(rows)) + 1;
        LweSample *ctxt_counter = new_gate_bootstrapping_ciphertext_array(counter_size, cloud_key->params);
        for (int i = 0; i < counter_size; ++i) {
            bootsCONSTANT(&ctxt_counter[i], 0, cloud_key);
        }

        LweSample *subset_test_result = new_gate_bootstrapping_ciphertext(cloud_key->params);
        for (int i = 0; i < rows; ++i) {
            somewhat_secure_subset_testing(subset_test_result, ptxt_query, ctxt_data_matrix[i], cols, cloud_key);
            secure_count(ctxt_counter, counter_size, subset_test_result, cloud_key);
        }
        secure_compare(result, ctxt_counter, ctxt_min_supp_count, counter_size, cloud_key);

        delete_gate_bootstrapping_ciphertext_array(counter_size, ctxt_counter);
        delete_gate_bootstrapping_ciphertext(subset_test_result);
    }

}
