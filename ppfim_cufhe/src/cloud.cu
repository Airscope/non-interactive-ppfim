//
// Created by z1y on 2019/9/27.
//

#include "cloud.cuh"

#include <iostream>

namespace ppfim {

    void SecureSubsetTesting(cufhe::Ctxt &out,
                             const cufhe::Ctxt *ctxt_query,
                             const cufhe::Ctxt *ctxt_trans,
                             const cufhe::Ctxt &ctxt_one,
                             uint32_t length,
                             cufhe::Stream *stream,
                             uint32_t stream_num) {
        
        cufhe::Copy(out, ctxt_one);
        cufhe::Ctxt *tmp = new cufhe::Ctxt[length];

        // Parallel part
        for (int i = 0; i < length; ++i) {
            cufhe::Not(tmp[i], ctxt_query[i], stream[i % stream_num]);
            cufhe::Or(tmp[i], tmp[i], ctxt_trans[i], stream[i % stream_num]);
        }
        
        cufhe::Synchronize();

        // Merging part
        for (int i = 0; i < length; ++i) {
            cufhe::And(out, tmp[i], out);
        }

        delete [] tmp;
        
    }

    
    void SomewhatSecureSubsetTesting(cufhe::Ctxt &out,
                                     const cufhe::Ptxt *ptxt_query,
                                     const cufhe::Ctxt *ctxt_trans,
                                     const cufhe::Ctxt &ctxt_one,
                                     uint32_t length,
                                     cufhe::Stream *stream,
                                     uint32_t stream_num) {
    
        cufhe::Copy(out, ctxt_one);
        for (int i = 0; i < length; ++ i) {
            if (ptxt_query[i].message_ == 1) {
                cufhe::And(out, out, ctxt_trans[i]);
            }
        }
        cufhe::Synchronize();
    }

    
    
    void SecureCount(cufhe::Ctxt *ctxt_counter,
                     const cufhe::Ctxt& ctxt_bit,
                     uint32_t length,
                     cufhe::Stream *stream,
                     uint32_t stream_num) {
    
        cufhe::Ctxt *carry = new cufhe::Ctxt[length];
        cufhe::Copy(carry[length - 1], ctxt_bit);
        for (int i = length - 2; i >= 0; -- i) {
            cufhe::And(carry[i], carry[i + 1], ctxt_counter[i + 1]);
        }
        
        cufhe::Synchronize();

        // Parallel part
        for (int i = 0; i < length; ++ i) {
            cufhe::Xor(ctxt_counter[i], ctxt_counter[i], carry[i], stream[i % stream_num]);
        }

        cufhe::Synchronize();
        
        delete [] carry;
    }

    void FastSecureCompare(cufhe::Ctxt &out,
                           const cufhe::Ctxt *lhs,
                           const cufhe::Ctxt *rhs,
                           const cufhe::Ctxt &ctxt_zero,
                           const cufhe::Ctxt &ctxt_one,
                           uint32_t length,
                           cufhe::Stream *stream,
                           uint32_t stream_num) {

        cufhe::Ctxt *aux = new cufhe::Ctxt[length]; 
        cufhe::Ctxt *aux2 = new cufhe::Ctxt[length];
        cufhe::Ctxt *aux3 = new cufhe::Ctxt[length];

        // Parallel part 1
        for (int i = 0; i < length; ++ i) {
            cufhe::Xnor(aux[i], lhs[i], rhs[i], stream[i % stream_num]);
        }

        cufhe::Synchronize();
        
        // DP
        cufhe::Copy(aux2[0], ctxt_one);        
        for (int i = 1; i < length; ++ i) {
            cufhe::And(aux2[i], aux[i - 1], aux2[i - 1]);
        }

        cufhe::Synchronize();

        // Parallel part 2
        for (int i = 0; i < length; ++ i) {
            cufhe::Not(aux3[i], lhs[i], stream[i % stream_num]);
            cufhe::And(aux3[i], rhs[i], aux3[i], stream[i % stream_num]);
            cufhe::And(aux3[i], aux3[i], aux2[i], stream[i % stream_num]);
        }

        cufhe::Synchronize();
        
        // Merging part
        cufhe::Copy(out, ctxt_zero);
        for (int i = 0; i < length; ++ i) {
            cufhe::Or(out, out, aux3[i]);
        }

        cufhe::Synchronize();

        delete [] aux;
        delete [] aux2;
        delete [] aux3;
    }
    
    
    
    void FreqItemsetMiningFirst(cufhe::Ctxt &out,
                                const std::vector<cufhe::Ctxt*> &ctxt_data_matrix,
                                uint32_t rows,
                                uint32_t cols,
                                const cufhe::Ctxt *ctxt_min_supp_count,
                                const cufhe::Ctxt *ctxt_query,
                                uint32_t counter_length,
                                const cufhe::Ctxt &ctxt_zero,
                                const cufhe::Ctxt &ctxt_one,
                                cufhe::Stream *stream,
                                uint32_t stream_num) {
        
        cufhe::Ctxt *counter = new cufhe::Ctxt[counter_length];
        cufhe::Ctxt *subset_test_result = new cufhe::Ctxt;

        for (int i = 0; i < counter_length; ++ i) {
            cufhe::Copy(counter[i], ctxt_zero);
        }
        for (int i = 0; i < rows; ++ i) {
            ppfim::SecureSubsetTesting(*subset_test_result, ctxt_query, ctxt_data_matrix[i],
                    ctxt_one, cols, stream, stream_num);
            ppfim::SecureCount(counter, *subset_test_result, counter_length, stream, stream_num);
        }
        ppfim::FastSecureCompare(out, counter, ctxt_min_supp_count, 
                ctxt_zero, ctxt_one, counter_length, stream, stream_num);

        delete [] counter;
        delete subset_test_result;
    }
 
    void FreqItemsetMiningSecond(cufhe::Ctxt &out,
                                 const std::vector<cufhe::Ctxt*> &ctxt_data_matrix,
                                 uint32_t rows,
                                 uint32_t cols,
                                 const cufhe::Ctxt *ctxt_min_supp_count,
                                 const cufhe::Ptxt *ptxt_query,
                                 uint32_t counter_length,
                                 const cufhe::Ctxt &ctxt_zero,
                                 const cufhe::Ctxt &ctxt_one,
                                 cufhe::Stream *stream,
                                 uint32_t stream_num) {
        
        cufhe::Ctxt *counter = new cufhe::Ctxt[counter_length];
        cufhe::Ctxt *subset_test_result = new cufhe::Ctxt;

        for (int i = 0; i < counter_length; ++ i) {
            cufhe::Copy(counter[i], ctxt_zero);
        }
        for (int i = 0; i < rows; ++ i) {
            ppfim::SomewhatSecureSubsetTesting(*subset_test_result, ptxt_query, ctxt_data_matrix[i],
                    ctxt_one, cols, stream, stream_num);
            ppfim::SecureCount(counter, *subset_test_result, counter_length, stream, stream_num);
        }
        ppfim::FastSecureCompare(out, counter, ctxt_min_supp_count, 
                ctxt_zero, ctxt_one, counter_length, stream, stream_num);

        delete [] counter;
        delete subset_test_result;
    }
    
    void DecToBin(cufhe::Ptxt* ret, int num, uint32_t length) {
        for (int i = 0; i < length; ++ i) {
            ret[length - i - 1].message_ = (num >> i) & 0x01;
        }
    }

    int BinToDec(const cufhe::Ptxt* num, uint32_t length) {
        int ret = 0;
        for (int i = 0; i < length; ++ i) {
            ret |= num[length - 1 - i].message_ << i;
        }
        return ret;
    }
    

}
