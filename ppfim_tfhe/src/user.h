//
// Created by z1y on 2019/9/25.
//

#ifndef PPFIM_USER_H
#define PPFIM_USER_H

#include <vector>
#include <string>
#include <tfhe/tfhe.h>


namespace ppfim {
    std::vector<std::string> split(const std::string &str, const std::string &delim);

    std::vector<std::vector<int>> load_data(const std::string &file_name, int rows, int cols);

    void encrypt_data(std::vector<LweSample *> &result,
                      int rows,
                      int cols,
                      const std::vector<std::vector<int>> &data_matrix,
                      const TFheGateBootstrappingSecretKeySet *secret_key);

    std::vector<std::vector<int>> decrypt_data(const std::vector<LweSample *> &ctxt_data,
                                               int rows,
                                               int cols,
                                               TFheGateBootstrappingSecretKeySet *secret_key);

    void ctxt_min_supp_count(LweSample *result,
                             int length,
                             int min_supp_count,
                             TFheGateBootstrappingSecretKeySet *secret_key);

    std::vector<int> dec_to_bin(int num, int length);

    int bin_to_dec(const std::vector<int> &num);
}

#endif //PPFIM_USER_H
