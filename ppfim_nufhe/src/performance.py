import nufhe
import cloud
import user
import miner
import time
import math

def main():
    context = nufhe.Context()
    secret_key, cloud_key = context.make_key_pair()
    vm = context.make_virtual_machine(cloud_key)
    file_name = "dataset_chess.txt"
    min_supp = 0.8
    running_times = 5
    trans_nums = [i for i in range(100, 1100, 100)] 
    items_nums = [i for i in range(10, 110, 10)]
    for m in trans_nums:
        n = 20
        k = math.floor(math.log2(m)) + 1
        print("Trans Number:", m, ", Items Number:", n)

        data_matrix = user.load_data(file_name, n, m)
        ctxt_data_matrix = user.encrypt_data(data_matrix, context, secret_key)
        
        ctxt_min_supp_count = user.ctxt_min_supp_count(min_supp, m, k, context, secret_key)

        query = miner.plaintext_query(n)
        ctxt_query = miner.ciphertext_query(n, context, secret_key)

        time_records_p1 = []
        time_records_p2 = []
        for i in range(running_times):
            start = time.time()
            cloud.freq_itemset_mining(ctxt_data_matrix, ctxt_min_supp_count, True, ctxt_query, vm)
            finish = time.time()
            time_records_p1.append(finish-start)
            
            start = time.time()
            cloud.freq_itemset_mining(ctxt_data_matrix, ctxt_min_supp_count, False, query, vm)
            finish = time.time()
            time_records_p2.append(finish-start)
        print("Protocol 1 time used: ", time_records_p1, "average time:",
                sum(time_records_p1)/len(time_records_p1), "seconds")
        print("Protocol 2 time used: ", time_records_p2, "average time:",
                sum(time_records_p2)/len(time_records_p2), "seconds\n")

    for n in items_nums:
        m = 1000
        k = math.floor(math.log2(m)) + 1
        print("Trans Number:", m, ", Items Number:", n)

        data_matrix = user.load_data(file_name, n, m)
        ctxt_data_matrix = user.encrypt_data(data_matrix, context, secret_key)
        
        ctxt_min_supp_count = user.ctxt_min_supp_count(min_supp, m, k, context, secret_key)

        query = miner.plaintext_query(n)
        ctxt_query = miner.ciphertext_query(n, context, secret_key)

        time_records_p1 = []
        time_records_p2 = []
        for i in range(running_times):
            start = time.time()
            cloud.freq_itemset_mining(ctxt_data_matrix, ctxt_min_supp_count, True, ctxt_query, vm)
            finish = time.time()
            time_records_p1.append(finish-start)
            
            start = time.time()
            cloud.freq_itemset_mining(ctxt_data_matrix, ctxt_min_supp_count, False, query, vm)
            finish = time.time()
            time_records_p2.append(finish-start)
        print("Protocol 1 time used: ", time_records_p1, "average time:",
                sum(time_records_p1)/len(time_records_p1), "seconds")
        print("Protocol 2 time used: ", time_records_p2, "average time:",
                sum(time_records_p2)/len(time_records_p2), "seconds\n")



if __name__ == "__main__":
    main()
