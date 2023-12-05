def sign_encrypt(x: str, z: str, y: str) -> int:
    load_key(z, y)
    return pow(int(x), mine_d, mine_n)


def sign_decrypt(x: str, z: str, y: str) -> int:
    load_key(z, y)
    return pow(int(x), other_e, other_n)


def encrypt(x: str, z: str, y: str) -> int:
    load_key(z, y)
    return pow(int(x), other_e, other_n)


def decrypt(x: str, z: str, y: str) -> int:
    load_key(z, y)
    return pow(int(x), mine_d, mine_n)


def load_key(z: str, y: str) -> None:
    file1 = z + "key.pub"
    file2 = z + "key.priv"
    file3 = y + "key.pub"
    global mine_n, mine_e, mine_d, other_e, other_n
    tmp = '' 
    with open(file1, "r") as f:
        for line in f:
            tmp += line
        tmp = tmp.split(',')
        mine_n = int(tmp[0])
        mine_e = int(tmp[1])
        tmp = ''

    with open(file2, "r") as f:
        for line in f:
            tmp += line
        tmp = tmp.split(',')
        mine_d = int(tmp[1])
        tmp = ''

    with open(file3, "r") as f:
        for line in f:
            tmp += line
        tmp = tmp.split(',')
        other_n = int(tmp[0])
        other_e = int(tmp[1])
        tmp = ''
