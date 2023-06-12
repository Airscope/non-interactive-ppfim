//
// Created by z1y on 2019/9/25.
//
#include <cassert>
#include <algorithm>

#include "user.cuh"
#include "cloud.cuh"

namespace ppfim {

    std::vector<std::string> Split(const std::string &str, const std::string &delim) {
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

    void LoadData(std::vector<cufhe::Ptxt *> &ret, 
                  const std::string &file_name, 
                  int rows, 
                  int cols) {

        assert(rows > 0 && cols > 0);
        
        for (int r = 0; r < rows; ++ r) {
            for (int c = 0; c < cols; ++ c) {
                ret[r][c].message_ = 0;
            }
        }

        FILE *f = fopen(file_name.c_str(), "r");
        assert(f != nullptr);
        int i = 0, j = 0;
        char line[1000];
        while (i < rows && fgets(line, sizeof(line), f) != nullptr) {
            auto labels = Split(line, " ");
            for (auto &label : labels) {
                j = std::stoi(label);
                if (j > cols) {
                    break;
                }
                ret[i][j - 1].message_ = 1; // Label begins from 1
            }
            ++i;
        }
        fclose(f);
    }

    void EncryptData(std::vector<cufhe::Ctxt *> &result,
                     int rows,
                     int cols,
                     const std::vector<cufhe::Ptxt *> &data_matrix,
                     const cufhe::PriKey &pri_key) {

        for (int i = 0; i < rows; ++i) {
            for (int j = 0; j < cols; ++j) {
                cufhe::Encrypt(result[i][j], data_matrix[i][j], pri_key);
            }
        }
    }


    void CtxtMinSuppCount(cufhe::Ctxt *ret,
                          uint32_t length,
                          uint32_t min_supp_count,
                          const cufhe::PriKey &pri_key) {
       
        cufhe::Ptxt *tmp = new cufhe::Ptxt[length];

        ppfim::DecToBin(tmp, min_supp_count, length);

        for (uint32_t i = 0; i < length; ++i) {
            cufhe::Encrypt(ret[i], tmp[i], pri_key);
        }

        delete [] tmp;
    }

}
