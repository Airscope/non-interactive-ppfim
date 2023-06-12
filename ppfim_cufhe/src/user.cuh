
#ifndef PPFIM_CUFHE_USER_CUH
#define PPFIM_CUFHE_USER_CUH

#include <string>
#include <vector>

#include "cufhe_gpu.cuh"

namespace ppfim {


    std::vector<std::string> Split(const std::string &str, const std::string &delim);

    void LoadData(std::vector<cufhe::Ptxt *> &ret, 
                  const std::string &file_name,
                  int rows,
                  int cols);

    void EncryptData(std::vector<cufhe::Ctxt *> &result,
                     int rows,
                     int cols,
                     const std::vector<cufhe::Ptxt *> &data_matrix,
                     const cufhe::PriKey &pri_key);

    void CtxtMinSuppCount(cufhe::Ctxt *ret,
                          uint32_t length,
                          uint32_t min_supp_count,
                          const cufhe::PriKey &pri_key);
}

#endif // PPFIM_CUFHE_USER_CUH
