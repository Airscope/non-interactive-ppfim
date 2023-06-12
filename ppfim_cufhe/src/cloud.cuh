//
// Created by z1y on 2019/9/27.
//

#ifndef PPFIM_CUFHE_CLOUD_CUH
#define PPFIM_CUFHE_CLOUD_CUH

#include <vector>

#include "cufhe_gpu.cuh"

namespace ppfim {

    void SecureSubsetTesting(cufhe::Ctxt &out,
                             const cufhe::Ctxt *ctxt_query,
                             const cufhe::Ctxt *ctxt_trans,
                             const cufhe::Ctxt &ctxt_one,
                             uint32_t length,
                             cufhe::Stream *stream,
                             uint32_t stream_num);

    void SomewhatSecureSubsetTesting(cufhe::Ctxt &out,
                                     const cufhe::Ptxt *ptxt_query,
                                     const cufhe::Ctxt *ctxt_trans,
                                     const cufhe::Ctxt &ctxt_one,
                                     uint32_t length,
                                     cufhe::Stream *stream,
                                     uint32_t stream_num);

    void SecureCount(cufhe::Ctxt *ctxt_counter,
                     const cufhe::Ctxt& ctxt_bit,
                     uint32_t length,
                     cufhe::Stream *stream,
                     uint32_t stream_num);

    
    void FastSecureCompare(cufhe::Ctxt &out,
                           const cufhe::Ctxt *lhs,
                           const cufhe::Ctxt *rhs,
                           const cufhe::Ctxt &ctxt_zero,
                           const cufhe::Ctxt &ctxt_one,
                           uint32_t length,
                           cufhe::Stream *stream,
                           uint32_t stream_num);
    
    void FreqItemsetMiningFirst(cufhe::Ctxt &out,
                                const std::vector<cufhe::Ctxt *> &ctxt_data_matrix,
                                uint32_t rows,
                                uint32_t cols,
                                const cufhe::Ctxt *ctxt_min_supp_count,
                                const cufhe::Ctxt *ctxt_query,
                                uint32_t counter_length,
                                const cufhe::Ctxt &ctxt_zero,
                                const cufhe::Ctxt &ctxt_one,
                                cufhe::Stream *stream,
                                uint32_t stream_num);
    
    void FreqItemsetMiningSecond(cufhe::Ctxt &out,
                                 const std::vector<cufhe::Ctxt *> &ctxt_data_matrix,
                                 uint32_t rows,
                                 uint32_t cols,
                                 const cufhe::Ctxt *ctxt_min_supp_count,
                                 const cufhe::Ptxt *ptxt_query,
                                 uint32_t counter_length,
                                 const cufhe::Ctxt &ctxt_zero,
                                 const cufhe::Ctxt &ctxt_one,
                                 cufhe::Stream *stream,
                                 uint32_t stream_num);

    void DecToBin(cufhe::Ptxt* ret, int num, uint32_t length);
    
    int BinToDec(const cufhe::Ptxt* num, uint32_t length);

}


#endif //PPFIM_CUFHE_CLOUD_CUH
