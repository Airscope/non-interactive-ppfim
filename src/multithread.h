//
// Created by z1y on 2019/9/30.
//

#ifndef PPFIM_MULTITHREAD_H
#define PPFIM_MULTITHREAD_H

#include <vector>
#include "tfhe/tfhe.h"

namespace ppfim {

    typedef struct {
        int begin;
        int end;
    } offset;

    void worker_first(LweSample *ret,
                      int counter_length,
                      const std::vector<LweSample *> &ctxt_data_matrix,
                      int index_begin,
                      int index_end,
                      const LweSample *ctxt_query,
                      int query_length,
                      const TFheGateBootstrappingCloudKeySet *cloud_key);

    void worker_second(LweSample *ret,
                       int counter_length,
                       const std::vector<LweSample *> &ctxt_data_matrix,
                       int index_begin,
                       int index_end,
                       const std::vector<int> &ptxt_query,
                       int query_length,
                       const TFheGateBootstrappingCloudKeySet *cloud_key);

    offset get_offset(int total_num, int threads_num, int id);

    void merge(LweSample *ret,
               const std::vector<LweSample *> &counters,
               int counter_length,
               const LweSample *ctxt_min_supp_count,
               const TFheGateBootstrappingCloudKeySet *cloud_key);

    void parallel_freq_itemset_mining_first(LweSample *result,
                                            int thread_num,
                                            const std::vector<LweSample *> &ctxt_data_matrix,
                                            int rows,
                                            const LweSample *ctxt_query,
                                            const LweSample *ctxt_min_supp_count,
                                            int counter_length,
                                            const TFheGateBootstrappingCloudKeySet *cloud_key);

    void parallel_freq_itemset_mining_second(LweSample *result,
                                             int thread_num,
                                             const std::vector<LweSample *> &ctxt_data_matrix,
                                             int rows,
                                             const std::vector<int> &ptxt_query,
                                             const LweSample *ctxt_min_supp_count,
                                             int counter_length,
                                             const TFheGateBootstrappingCloudKeySet *cloud_key);
}


#endif //PPFIM_MULTITHREAD_H
