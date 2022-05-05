import random
import re
import numpy as np
import math
import gmpy2


def upper_sequence(seq_length):
    array = []
    while len(array) < seq_length:
        right_border_for_s1 = (2**seq_length) - 1
        s1 = random.randint(1, right_border_for_s1)
        a = sum(array, 0) + s1
        array.append(a)
    return array


def gcd(a, b):
    if b > a:
        c = b
        b = a
        a = c
    r = (a % b)
    while r > 0:
        a = b
        b = r
        r = (a % b)
    return b


def crypt_arr(arr, w_j, m_j):
    for array_index in range(0, len(sequence_copy), 1):
        arr[array_index] = (arr[array_index] * w_j) % m_j
    return arr


def generate_index_permutation(arr):
    temp = [index for index in range(0, len(arr), 1)]
    random.shuffle(temp)
    return temp


def apply_permutation_to_array(arr, permutation):
    temp = []
    for array_index in permutation:
        temp.append(arr[array_index])
    return temp


def string_to_int_array(string):
    return gmpy2.mpz(string)


def bits_to_char(arr):
    int_val = 0
    for arr_index in range(-len(arr), 0, 1):
        int_val += (2**(abs(arr_index)-1))*int(arr[arr_index])
    return chr(int_val)


def expand_euclid(n, mod):
    if n > mod:
        n = n % mod
    if n == 0:
        return 0
    x2 = 1
    x1 = 0
    y2 = 0
    y1 = 1
    while n > 0:
        q = math.floor(mod//n)
        r = mod - q * n
        x = x2 - q * x1
        y = y2 - q * y1
        mod = n
        n = r
        x2 = x1
        x1 = x
        y2 = y1
        y1 = y
    y = y2
    return y


if __name__ == '__main__':
    change_pass = input("Change password? [y/n]\n")
    if change_pass == 'y':
        N = int(input("Enter size of key: "))
        sequence = upper_sequence(N)
        sequence_copy = sequence.copy()
        number_of_rounds = int(input("Enter number of rounds: "))
        M = []
        W = []
        for j in range(0, number_of_rounds, 1):
            M.append(sum(sequence_copy, 0) + 1)
            w = random.randint(1, M[j])
            while gcd(M[j], w) != 1:
                w = random.randint(1, M[j])
            W.append(w)
            sequence_copy = crypt_arr(sequence_copy, W[j], M[j])
        print("\n\n", sequence_copy)
        mix = generate_index_permutation(sequence_copy)
        shuffled = apply_permutation_to_array(sequence_copy, mix)
        print(shuffled)

        f = open('Secret_key.txt', 'w')
        f.write(f'{mix}\n{M}\n{W}\n{sequence}')
        f.close()

        f = open('Public_key.txt', 'w')
        f.write(f'{shuffled}')
        f.close()
        print("\n\nSecret and public keys have been changed.")
        print(f"Secret key is (pi: {mix},\n M: {M},\n W: {W},\n a(0): {sequence})")
        print(f"Public key is: {sequence_copy}")
    else:
        print("Using old keys.")
        f = open('Secret_key.txt', 'r')
        secret = f.readlines()
        for i in range(0, len(secret), 1):
            secret[i] = re.sub(r'[\[\]]', ' ', secret[i])
            secret[i] = re.sub(r'\n', '', secret[i])
        vector = np.vectorize(string_to_int_array)

        Mix = list(vector(re.split(r',', secret[0])))
        M = list(vector(re.split(r',', secret[1])))
        W = list(vector(re.split(r',', secret[2])))
        a0 = list(vector(re.split(r',', secret[3])))

        f = open('Public_key.txt', 'r')
        public_key = f.read()
        public_key = re.sub(r'[\[\]]', ' ', public_key)
        public_key = re.sub(r'\n', '', public_key)
        public_key = list(vector(re.split(r',', public_key)))

        # Crypt
        msg = input("Enter your message: ")
        # msg = ""
        bin_msg = ''.join(format(x, '08b') for x in bytearray(msg, 'utf-8'))
        #  08b = 8bits - size of char in ASCII, if UNICODE - 32?

        print(f'{msg}:\nis {bin_msg}')
        start_bin_msg = bin_msg[:(len(bin_msg) % (len(public_key)))]
        bin_msg = bin_msg[(len(bin_msg) % (len(public_key))):]
        print(f'{msg}:\nis {start_bin_msg} {bin_msg}')
        amount_of_blocks = int(len(bin_msg)/len(public_key))
        pieces = np.array_split(list(bin_msg), amount_of_blocks)
        for j in range(0, len(pieces), 1):
            pieces[j] = list(vector(pieces[j]))
        crypt_text = []
        for el in pieces:
            tmp = 0
            for i in range(0, len(el), 1):
                tmp += gmpy2.mpz(public_key[i])*el[i]
            crypt_text.append(tmp)
        print(f"Encrypting message: start bits {start_bin_msg} and cipher {crypt_text}")

        # Decrypt
        number_of_rounds = len(W) - 1
        text_to_bin = []
        for d in crypt_text:
            for j in range(number_of_rounds, -1, -1):
                _W_ = expand_euclid(W[j], M[j]) % M[j]
                d = (gmpy2.mpz(_W_)*d) % M[j]
            text_to_bin.append(d)
        bin_text = []
        for val in text_to_bin:
            SUM = 0
            decrypt_block = np.zeros(len(a0)).astype(int)
            for l in range(-1, -len(a0)-1, -1):
                SUM += a0[l]
                if SUM <= val:
                    decrypt_block[l] = 1
                else:
                    SUM -= a0[l]
                    decrypt_block[l] = 0
            decrypt_block = apply_permutation_to_array(decrypt_block, Mix)
            bin_text.append(decrypt_block)
        decrypt_str = np.reshape(bin_text, len(bin_text)*len(a0))
        decrypt_str = np.hstack([list(start_bin_msg), decrypt_str])
        print(f"result bin: {decrypt_str}")

        decrypt_str = np.reshape(decrypt_str, (int(len(decrypt_str)/8), 8))

        get_msg = ''
        for line in decrypt_str:
            get_msg += bits_to_char(line)
        print(f"Decrypted massege:\n{get_msg}")
