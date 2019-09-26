//
// Created by z1y on 2019/9/25.
//

#ifndef PPFIM_MINER_H
#define PPFIM_MINER_H

#include <vector>

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

namespace ppfim {
    std::vector <int32_t> plaintext_query(int32_t length);

    void ciphertext_query(LweSample *result,
                          int32_t length,
                          TFheGateBootstrappingSecretKeySet *secret_key);

}

#endif //PPFIM_MINER_H
