import nufhe
import cloud

def load_data(file_name, cols, rows):
    ret = [[0 for i in range(cols)] for j in range(rows)]
    # print(len(ret), len(ret[0]))
    with open(file_name, "r") as f:
        i = 0
        for line in f.readlines():
            if (i >= rows):
                break
            features = line.split()
            for feature in features:
                j = int(feature)
                if (j > cols):
                    break
                ret[i][j-1] = 1
            i += 1
    return ret


def encrypt_data(data_matrix, context, secret_key):
    m = len(data_matrix)
    n = len(data_matrix[0])
    ret = [[context.encrypt(secret_key, [data_matrix[row][col]]) for col in range(n)] for row in
            range(m)]
    return ret


def ctxt_min_supp_count(min_supp, rows, length, context, secret_key):
    min_supp_count = cloud.dec_to_bin(int(min_supp*rows), length)
    return [context.encrypt(secret_key, [min_supp_count[i]]) for i in range(len(min_supp_count))]


def test_load_data():
    print(load_data("dataset_chess.txt", 10, 10))


def test_all():
    test_load_data()


if __name__ == "__main__":
    test_all()
    

