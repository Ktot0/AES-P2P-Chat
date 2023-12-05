from random import randint


def modular_pow(x, y, p) -> int:
    # x = a, y = k, p = n
    res = 1
    x = x % p 
    while y > 0:
        if y & 1:
            res = (res * x) % p   # if y is odd
        y = y >> 1    # y becomes even 
        x = (x * x) % p
    return res


def test_miller_rabin(k, n) -> bool:
    a = 2 + randint(1, n - 4)  # Random a (n > 4)
    x = modular_pow(a, k, n)  # a^k(%n)
    if x == 1 or x == n - 1:
        return True
    while k != n - 1:
        x = (x * x) % n
        k *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True    
    return False


def test_prime(n, acc) -> bool:
    # Edge cases
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True  
    k = n - 1
    while k % 2 == 0:
        k //= 2
    for _ in range(acc):
        if not test_miller_rabin(k, n):
            return False
    return True
