#include "miner.cuh"

namespace ppfim {

void PlaintextQuery(cufhe::Ptxt *ret, uint32_t length) {
    for (uint32_t i = 0; i < length; ++ i) {
        ret[i].message_ = 0;
    }
    ret[0].message_ = 1;
}

void CiphertextQuery(cufhe::Ctxt *ret,
                     uint32_t length,
                     const cufhe::PriKey &pri_key) {

    cufhe::Ptxt *query = new cufhe::Ptxt[length];
    PlaintextQuery(query, length);
    for (uint32_t i = 0; i < length; ++ i) {
        cufhe::Encrypt(ret[i], query[i], pri_key);
    }

    delete [] query;
}

} // namespace ppfim
