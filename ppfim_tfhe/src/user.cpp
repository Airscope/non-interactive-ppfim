//
// Created by z1y on 2019/9/25.
//
#include <cassert>
#include <algorithm>

#include "user.h"

namespace ppfim {

    std::vector<std::string> split(const std::string &str, const std::string &delim) {
        size_t last = 0;
        size_t index = str.find_first_of(delim, last);
        std::vector<std::string> ret;
        while (index != std::string::npos) {
            ret.push_back(str.substr(last, index - last));
            last = index + 1;
            index = str.find_first_of(delim, last);
        }
        if (index - last > 0) {
            ret.push_back(str.substr(last, index - last));
        }
        return ret;
    }

    std::vector<std::vector<int>> load_data(const std::string &file_name, int rows, int cols) {
        assert(rows > 0 && cols > 0);
        std::vector<std::vector<int>> ret(rows, std::vector<int>(cols));
        FILE *f = fopen(file_name.c_str(), "r");
        assert(f != nullptr);
        int i = 0, j = 0;
        char line[1000];
        while (i < rows && fgets(line, sizeof(line), f) != nullptr) {
            auto labels = split(line, " ");
            for (auto &label : labels) {
                j = std::stoi(label);
                if (j > cols) {
                    break;
                }
                ret[i][j - 1] = 1; // Label begins from 1
            }
            ++i;
        }
        fclose(f);
        return ret;
    }

    void encrypt_data(std::vector<LweSample *> &result,
                      int rows,
                      int cols,
                      const std::vector<std::vector<int>> &data_matrix,
                      const TFheGateBootstrappingSecretKeySet *secret_key) {
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < cols; ++j) {
                bootsSymEncrypt(&(result[i][j]), data_matrix[i][j], secret_key);
            }
        }
    }

    std::vector<std::vector<int>> decrypt_data(const std::vector<LweSample *> &ctxt_data,
                                               int rows,
                                               int cols,
                                               TFheGateBootstrappingSecretKeySet *secret_key) {
        int decrypted = 0;
        std::vector<std::vector<int>> ret(rows, std::vector<int>(cols));
        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < cols; ++j) {
                decrypted = bootsSymDecrypt(&(ctxt_data[i][j]), secret_key);
                ret[i][j] = decrypted;
            }
        }
        return ret;
    }

    void ctxt_min_supp_count(LweSample *result,
                             int length,
                             int min_supp_count,
                             TFheGateBootstrappingSecretKeySet *secret_key) {
        auto bin_min_supp_count = ppfim::dec_to_bin(min_supp_count, length);
        for (int i = 0; i < length; ++i) {
            bootsSymEncrypt(&result[i], bin_min_supp_count[i], secret_key);
        }
    }

    std::vector<int> dec_to_bin(int num, int length) {
        assert(length > 0);
        std::vector<int> ret;
        for (int i = 0; i < length; ++i)
            ret.push_back((num >> i) & 1);
        std::reverse(ret.begin(), ret.end());
        return ret;
    }

    int bin_to_dec(const std::vector<int> &num) {
        int ret = 0, p = 1;
        for (int i = num.size() - 1; i >= 0; --i) {
            ret += num[i] * p;
            p *= 2;
        }
        return ret;
    }
}