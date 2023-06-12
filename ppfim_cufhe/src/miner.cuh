
#ifndef PPFIM_CUFHE_MINER_CUH
#define PPFIM_CUFHE_MINER_CUH

#include "cufhe_gpu.cuh"

namespace ppfim {

void PlaintextQuery(cufhe::Ptxt *ret, uint32_t length);

void CiphertextQuery(cufhe::Ctxt *ret,
                     uint32_t length,
                     const cufhe::PriKey &pri_key);

}

#endif // PPFIM_CUFHE_MINER_CUH
