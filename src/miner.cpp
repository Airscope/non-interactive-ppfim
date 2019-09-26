//
// Created by z1y on 2019/9/25.
//


#include <cassert>

#include "miner.h"

namespace ppfim {
    std::vector<int> plaintext_query(int length) {
        assert(length > 0);
        std::vector<int32_t> ret(length, 0);
        ret[0] = 1;
        return ret;
    }

    void ciphertext_query(LweSample *result,
                          int length,
                          TFheGateBootstrappingSecretKeySet *secret_key) {

        auto query = plaintext_query(length);
        for (int i = 0; i < length; ++i) {
            bootsSymEncrypt(&result[i], query[i], secret_key);
        }
    }
}
