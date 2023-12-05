from random import randint
import miller_rabin as mr


def greatest_common_divisor(x, y) -> int:
    while y:
        x, y = y, x % y
    return x


def generate(x):
    file1 = x + "key.pub"
    file2 = x + "key.priv"
    acc = 4  # Accuratezza
    i = int('1' * 128)
    j = int('9' * 128)

    p = randint(i, j)
    while not mr.test_prime(p, acc):
        p = randint(i, j)

    q = randint(i, j)
    while not mr.test_prime(q, acc):
        q = randint(i, j)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    while greatest_common_divisor(e, phi_n) != 1:
        e = randint(1, phi_n)

    d = pow(e, -1, phi_n)

    with open(file1, "w") as f:
        f.write(str(n) + "," + str(e))
    with open(file2, "w") as f1:
        f1.write(str(n) + "," + str(d))
