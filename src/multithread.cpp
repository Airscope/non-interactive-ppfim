//
// Created by z1y on 2019/9/30.
//

#include <cassert>
#include <thread>

#include "multithread.h"
#include "cloud.h"

namespace ppfim {
    void worker_first(LweSample *ret,
                      int counter_length,
                      std::vector<LweSample *>::iterator begin,
                      std::vector<LweSample *>::iterator end,
                      const LweSample *ctxt_query,
                      int query_length,
                      const TFheGateBootstrappingCloudKeySet *cloud_key) {

        LweSample *subset_test_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        for (auto iter = begin; iter != end; ++iter) {
            ppfim::secure_subset_testing(subset_test_result, ctxt_query, query_length, *iter, query_length, cloud_key);
            ppfim::secure_count(ret, counter_length, subset_test_result, cloud_key);
        }
        delete_gate_bootstrapping_ciphertext(subset_test_result);
    }

    void worker_second(LweSample *ret,
                       int counter_length,
                       std::vector<LweSample *>::iterator begin,
                       std::vector<LweSample *>::iterator end,
                       const std::vector<int> &ptxt_query,
                       int query_length,
                       const TFheGateBootstrappingCloudKeySet *cloud_key) {

        LweSample *subset_test_result = new_gate_bootstrapping_ciphertext(cloud_key->params);

        for (auto iter = begin; iter != end; ++iter) {
            ppfim::somewhat_secure_subset_testing(subset_test_result, ptxt_query, query_length, *iter, query_length,
                                                  cloud_key);
            ppfim::secure_count(ret, counter_length, subset_test_result, cloud_key);
        }
        delete_gate_bootstrapping_ciphertext(subset_test_result);
    }

    offset get_offset(int total_num, int threads_num, int id) {
        assert(threads_num > 0 && total_num > 0);
        assert(id >= 0 && id < threads_num);
        int step = total_num / threads_num;
        if (total_num % id != 0)
            step += 1;
        offset ofs;
        ofs.begin = step * id;
        ofs.end = step * (id + 1);
        if (ofs.end > total_num)
            ofs.end = total_num;
        return ofs;
    }

    void merge(LweSample *ret,
               const std::vector<LweSample *> &counters,
               int counter_length,
               const LweSample *ctxt_min_supp_count,
               const TFheGateBootstrappingCloudKeySet *cloud_key) {

        LweSample *sum = new_gate_bootstrapping_ciphertext_array(counter_length, cloud_key->params);
        for (int i = 0; i < counters.size(); ++i) {
            secure_add(sum, sum, counters[i], counter_length, cloud_key);
        }
        secure_compare(ret, sum, ctxt_min_supp_count, counter_length, cloud_key);
        delete_gate_bootstrapping_ciphertext_array(counter_length);
    }

    void parallel_freq_itemset_mining_first(LweSample *result,
                                            int thread_num,
                                            const std::vector<LweSample *> &ctxt_data_matrix,
                                            int rows,
                                            int cols,
                                            const LweSample *ctxt_query,
                                            const LweSample *ctxt_min_supp_count,
                                            int counter_length,
                                            const TFheGateBootstrappingCloudKeySet *cloud_key) {

        std::vector<std::thread> threads(thread_num);
        std::vector<LweSample *> counters(thread_num);
        for (int i = 0; i < thread_num; ++i) {
            counters[i] = new_gate_bootstrapping_ciphertext_array(counter_length, cloud_key->params);
        }
        auto iter = ctxt_data_matrix.begin();
        offset ofs;
        for (int i = 0; i < thread_num; ++i) {
            ofs = get_offset(rows, thread_num, i);
            threads[i] = std::thread(()
            [&counters, =] {
                worker_first(counters[i], counter_length, iter + ofs.begin, iter + ofs.end, ctxt_query, cols,
                             cloud_key);
            });
        }

        for (auto &th : threads) {
            if (th.joinable())
                th.join();
        }

        merge(result, counters, counter_length, ctxt_min_supp_count, cloud_key);

        for (int i = 0; i < thread_num; ++i) {
            delete_gate_bootstrapping_ciphertext_array(counter_length, counters[i])
        }
    }
}