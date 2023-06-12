import nufhe
import random

def plaintext_query(length):
    assert(length > 0)
    ret = [0 for i in range(length)]
    ret[0] = 1
    return ret

def ciphertext_query(length, context, secret_key):
    assert(length > 0)
    ptxt_query = plaintext_query(length)
    return [context.encrypt(secret_key, [ptxt_query[i]]) for i in range(length)]

if __name__ == '__main__':
    print("Testing miner.py ...")
    test_times = 10
    context = nufhe.Context()
    secret_key, cloud_key = context.make_key_pair()
    test_result = True
    for i in range(test_times):
        length = random.randint(1, 101)
        ptxt_query = plaintext_query(length)
        ctxt_query = ciphertext_query(length, context, secret_key)
        result_bits = context.decrypt(secret_key, ctxt_query)
        test_result = test_result and all(ptxt_query == result_bits)
    if test_result:
        print ("PASS")
    else:
        print ("FAIL")

