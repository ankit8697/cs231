def diffie_hellman():
    A = 46
    g = 17
    p = 61
    for i in range(100):
        if A == pow(g, i) % p:
            print('the answer is: ', i, ' this means A is: ', pow(g, i) % p)
        else:
            print('tried ', i, 'but failed. Value of A is: ', pow(g, i) % p)

def rsa_cracking():
    e_bob, n_bob = 31, 4661
    d_bob = 0
    ciphertext = [2677, 4254, 1152, 4645, 4227, 1583, 2252, 426, 3492, 4227, 3889, 1789, 4254, 1704, 1301, 4227, 1420, 1789, 1821, 1466, 4227, 2252, 3303, 1420, 2234, 4227, 4227, 1789, 1420, 1420, 4402, 1466, 4070, 3278, 3278, 414, 414, 414, 2234, 1466, 1704, 1789, 2955, 4254, 1821, 4254, 4645, 2234, 1704, 2252, 3282, 3278, 426, 2991, 2252, 1604, 3278, 1152, 4645, 1704,
                  1789, 1821, 4484, 4254, 1466, 3278, 1512, 3602, 1221, 1872, 3278, 1221, 1512, 3278, 4254, 1435, 3282, 1152, 1821, 2991, 1945, 1420, 4645, 1152, 1704, 1301, 1821, 2955, 1604, 1945, 1221, 2234, 1789, 1420, 3282, 2991, 4227, 4410, 1821, 1301, 4254, 1466, 3454, 4227, 4410, 2252, 3303, 4645, 4227, 3815, 4645, 1821, 4254, 2955, 2566, 3492, 4227, 3563, 2991, 1821, 1704, 4254]
    for d in range(10000):
        if (e_bob * d) % 4524 == 1:
            print('Yay the value of d is: ', d)
            d_bob = d
            break

    if d_bob != 0:
        plaintext = []
        for i in ciphertext:
            plain = pow(i, d_bob) % n_bob
            plaintext.append(chr(plain))
        print("".join(plaintext))
