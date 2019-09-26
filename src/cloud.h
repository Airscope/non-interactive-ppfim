//
// Created by z1y on 2019/9/25.
//

#ifndef PPFIM_CLOUD_H
#define PPFIM_CLOUD_H

#include <vector>

#include <tfhe/tfhe.h>

namespace ppfim {
    void secure_subset_testing(LweSample *result,
                               const LweSample *ctxt_query,
                               const LweSample *ctxt_trans,
                               int length,
                               const TFheGateBootstrappingCloudKeySet *cloud_key);

    void somewhat_secure_subset_testing(LweSample *result,
                                        const std::vector<int> &ptxt_query,
                                        const LweSample *ctxt_trans,
                                        int length,
                                        const TFheGateBootstrappingCloudKeySet *cloud_key);

    void secure_count(LweSample *ctxt_counter,
                      int length,
                      const LweSample *ctxt_bit,
                      const TFheGateBootstrappingCloudKeySet *cloud_key);

    void secure_compare(LweSample *result,
                        const LweSample *lhs,
                        const LweSample *rhs,
                        int length,
                        const TFheGateBootstrappingCloudKeySet *cloud_key);

    void freq_itemset_mining_first(LweSample *result,
                                   const std::vector<LweSample *> &ctxt_data_matrix,
                                   int rows,
                                   int cols,
                                   const LweSample *ctxt_query,
                                   const LweSample *ctxt_min_supp_count,
                                   const TFheGateBootstrappingCloudKeySet *cloud_key);

    void freq_itemset_mining_second(LweSample *result,
                                    const std::vector<LweSample *> &ctxt_data_matrix,
                                    int rows,
                                    int cols,
                                    const std::vector<int> &ptxt_query,
                                    const LweSample *ctxt_min_supp_count,
                                    const TFheGateBootstrappingCloudKeySet *cloud_key);

}

#endif //PPFIM_CLOUD_H
