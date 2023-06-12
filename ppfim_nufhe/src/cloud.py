import nufhe
import random
import math
import time

def trivial_subset_testing(query, trans):
    assert(len(query) == len(trans))
    ret = True
    for i in range(len(query)):
        ret = ret and ((not query[i]) or trans[i])
    return ret


def secure_subset_testing(ctxt_query, ctxt_trans, vm):
    assert(len(ctxt_query) == len(ctxt_trans))
    ret = vm.gate_constant([1])
    for i in range(len(ctxt_query)):
        tmp = vm.gate_orny(ctxt_query[i], ctxt_trans[i]) # (not x) or y
        ret = vm.gate_and(ret, tmp)
    return ret


def test_secure_subset_testing(vm, secret_key, context):
    test_times = 10
    print("Test secure subset testing algorithm", test_times, "times ...")
    test_result = True
    for i in range(test_times):
        length = random.randint(1, 20)
        query = [random.choice([False, True]) for j in range(length)]
        trans = [random.choice([False, True]) for j in range(length)]
        ctxt_query = [context.encrypt(secret_key, [query[j]]) for j in range(length)]
        ctxt_trans = [context.encrypt(secret_key, [trans[j]]) for j in range(length)]
        trivial_result = trivial_subset_testing(query, trans)
        secure_result = context.decrypt(secret_key, 
                secure_subset_testing(ctxt_query, ctxt_trans,vm))
        test_result = test_result and (trivial_result == secure_result)

    if test_result:
        print("PASS")
    else:
        print("FAIL")


def somewhat_secure_subset_testing(ptxt_query, ctxt_trans, vm):
    assert(len(ptxt_query) == len(ctxt_trans))
    ret = vm.gate_constant([1])
    for i in range(len(ptxt_query)):
        if ptxt_query[i] == 1:
            ret = vm.gate_and(ret, ctxt_trans[i])
    return ret


def test_somewhat_secure_subset_testing(vm, secret_key, context):
    test_times = 10
    print("Test somewhat secure subset testing algorithm", test_times, "times ...")
    test_result = True
    for i in range(test_times):
        length = random.randint(1, 20)
        query = [random.choice([False, True]) for j in range(length)]
        trans = [random.choice([False, True]) for j in range(length)]
        ctxt_trans = [context.encrypt(secret_key, [trans[j]]) for j in range(length)]
        trivial_result = trivial_subset_testing(query, trans)
        secure_result = context.decrypt(secret_key, 
                somewhat_secure_subset_testing(query, ctxt_trans,vm))
        test_result = test_result and (trivial_result == secure_result)

    if test_result:
        print("PASS")
    else:
        print("FAIL")


# Highest bit is on the leftest position
def dec_to_bin(num, length):
    ret = [(num >> i) & 1 for i in range(length)]
    return list(reversed(ret))


def bin_to_dec(bin_num):
    ret = 0
    a = 1
    for i in range(len(bin_num)-1, -1, -1):
        ret += bin_num[i] * a
        a *= 2
    return ret


def secure_count(ctxt_counter, ctxt_bit, vm):
    carry = vm.gate_copy(ctxt_bit)
    for i in range(len(ctxt_counter)-1, -1, -1):
        tmp = vm.gate_copy(ctxt_counter[i])
        ctxt_counter[i] = vm.gate_xor(ctxt_counter[i], carry)
        carry = vm.gate_and(carry, tmp)


def trivial_count(counter, bit):
    carry = bit
    for i in range(len(counter)-1, -1, -1):
        tmp = counter[i]
        counter[i] = ((not counter[i]) and carry) or (counter[i] and (not carry))
        carry = carry and tmp


def test_secure_count(vm, secret_key, context):
    test_times = 10
    print("Test secure count algorithm", test_times, "times ...")
    test_result = True
    for i in range(test_times):
        length = random.randint(1, 20)
        counter = [random.choice([False, True]) for j in range(length)]
        bit = random.choice([False, True])
        # print ("counter before:", counter)
        # print ("bit:", bit)
        ctxt_counter = [context.encrypt(secret_key, [counter[j]]) for j in range(length)]
        ctxt_bit = context.encrypt(secret_key, [bit])
        secure_count(ctxt_counter, ctxt_bit, vm)
        trivial_count(counter, bit)
        decrypted_counter = [context.decrypt(secret_key, ctxt_counter[j]) for j in range(length)]
        # print ("counter after:", counter, "\n")
        test_result = test_result and (decrypted_counter == counter)

    if test_result:
        print("PASS")
    else:
        print("FAIL")


def secure_compare(ctxt_num1, ctxt_num2, vm):
    assert(len(ctxt_num1) == len(ctxt_num2))
    ret = vm.gate_andny(ctxt_num1[0], ctxt_num2[0]) # (not x) and y
    for i in range(1, len(ctxt_num1)):
        tmp = vm.gate_andny(ctxt_num1[i], ctxt_num2[i])
        for j in range(i):
            tmp2 = vm.gate_xnor(ctxt_num1[j], ctxt_num2[j])
            tmp = vm.gate_and(tmp, tmp2)
        ret = vm.gate_xor(ret, tmp)
    return ret


def test_secure_compare(vm, secret_key, context):
    test_times = 10
    print("Test secure compare algorithm", test_times, "times ...")
    test_result = True
    for i in range(test_times):
        length = 10
        dec_num1 = random.randint(1, 1000)
        dec_num2 = random.randint(1, 1000)
        bin_num1 = dec_to_bin(dec_num1, length)
        bin_num2 = dec_to_bin(dec_num2, length)
        ctxt_num1 = [context.encrypt(secret_key, [bin_num1[j]]) for j in range(length)]
        ctxt_num2 = [context.encrypt(secret_key, [bin_num2[j]]) for j in range(length)]
        cmp_result = context.decrypt(secret_key, 
                secure_compare(ctxt_num1, ctxt_num2, vm))
        test_result = test_result and (cmp_result == (dec_num1 < dec_num2))

    if test_result:
        print("PASS")
    else:
        print("FAIL")


def freq_itemset_mining(data_ctxt_matrix, ctxt_min_supp_count, 
        protocol_type_first, query, vm):

    m = len(data_ctxt_matrix)
    counter_size = math.floor(math.log2(m)) + 1
    ctxt_counter = [vm.gate_constant([0]) for i in range(counter_size)]
    for i in range(m):
        if protocol_type_first:
            subset_test_result = secure_subset_testing(query, data_ctxt_matrix[i], vm)
            secure_count(ctxt_counter, subset_test_result, vm)
        else:
            subset_test_result = somewhat_secure_subset_testing(query, data_ctxt_matrix[i], vm)
            secure_count(ctxt_counter, subset_test_result, vm)
    return secure_compare(ctxt_counter, ctxt_min_supp_count, vm)


def trivial_freq_itemset_mining(data_matrix, min_supp, query):
    m = len(data_matrix)
    counter_size = math.floor(math.log2(m)) + 1
    counter = [0 for i in range(counter_size)]
    for i in range(m):
        subset_test_result = trivial_subset_testing(query, data_matrix[i])
        trivial_count(counter, subset_test_result)
    return bin_to_dec(counter) < min_supp * m


def test_freq_itemset_mining(vm, secret_key, context):
    test_times = 10
    print("Test freq itemset mining protocols", test_times, "times ...")
    test_result = True
    for i in range(test_times):
        cols = 20 # random.randint(10, 50)
        rows = 1000 #random.randint(10, 50)
        k = math.floor(math.log2(rows)) + 1
        data_matrix = [
                [random.choice([False, True]) for col in range(cols)]
                for row in range(rows) ]
        ctxt_data_matrix = [ 
                [context.encrypt(secret_key, [data_matrix[row][col]]) for col in range(cols)]
                for row in range(rows) ]
        min_supp = random.randint(1,101) / 100
        min_supp_count = int(min_supp * rows)
        bin_min_supp_count = dec_to_bin(min_supp_count, k)
        ctxt_min_supp_count = [context.encrypt(secret_key, [bin_min_supp_count[j]]) for j in
                range(len(bin_min_supp_count))]
        
        query = [random.choice([False,True]) for j in range(cols)]
        ctxt_query = [context.encrypt(secret_key, [query[j]]) for j in range(cols)]
        
        ctxt_protocol1_result = freq_itemset_mining(ctxt_data_matrix, ctxt_min_supp_count, True, 
                ctxt_query, vm)
        ctxt_protocol2_result = freq_itemset_mining(ctxt_data_matrix, ctxt_min_supp_count, False, 
                query, vm)
        trivial_result = trivial_freq_itemset_mining(data_matrix, min_supp, query)

        ptxt_protocol1_result = context.decrypt(secret_key, ctxt_protocol1_result)
        ptxt_protocol2_result = context.decrypt(secret_key, ctxt_protocol2_result)
        test_result = test_result and (ptxt_protocol1_result == ptxt_protocol2_result)\
                and (trivial_result == ptxt_protocol1_result)

    if test_result:
        print("PASS")
    else:
        print("FAIL")


def test_all():
    context = nufhe.Context()
    secret_key, cloud_key = context.make_key_pair()
    vm = context.make_virtual_machine(cloud_key)

    test_secure_subset_testing(vm, secret_key, context)
    test_somewhat_secure_subset_testing(vm, secret_key, context)
    test_secure_count(vm, secret_key, context)
    test_secure_compare(vm, secret_key, context)
    test_freq_itemset_mining(vm, secret_key, context)


if __name__ == '__main__':
    test_all()

