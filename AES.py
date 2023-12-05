import binascii
from typing import List

INITIALIZATION_VECTOR = '108B5EE7FEC0C9FAD197E32155466031'

SBOX = [
        ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76'],
        ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
        ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
        ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
        ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
        ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
        ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
        ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
        ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
        ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
        ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
        ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
        ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
        ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
        ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
        ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
        ]

SBOX_INVERSE = [
        ['52', '09', '6a', 'd5', '30', '36', 'a5', '38', 'bf', '40', 'a3', '9e', '81', 'f3', 'd7', 'fb'],
        ['7c', 'e3', '39', '82', '9b', '2f', 'ff', '87', '34', '8e', '43', '44', 'c4', 'de', 'e9', 'cb'],
        ['54', '7b', '94', '32', 'a6', 'c2', '23', '3d', 'ee', '4c', '95', '0b', '42', 'fa', 'c3', '4e'],
        ['08', '2e', 'a1', '66', '28', 'd9', '24', 'b2', '76', '5b', 'a2', '49', '6d', '8b', 'd1', '25'],
        ['72', 'f8', 'f6', '64', '86', '68', '98', '16', 'd4', 'a4', '5c', 'cc', '5d', '65', 'b6', '92'],
        ['6c', '70', '48', '50', 'fd', 'ed', 'b9', 'da', '5e', '15', '46', '57', 'a7', '8d', '9d', '84'],
        ['90', 'd8', 'ab', '00', '8c', 'bc', 'd3', '0a', 'f7', 'e4', '58', '05', 'b8', 'b3', '45', '06'],
        ['d0', '2c', '1e', '8f', 'ca', '3f', '0f', '02', 'c1', 'af', 'bd', '03', '01', '13', '8a', '6b'],
        ['3a', '91', '11', '41', '4f', '67', 'dc', 'ea', '97', 'f2', 'cf', 'ce', 'f0', 'b4', 'e6', '73'],
        ['96', 'ac', '74', '22', 'e7', 'ad', '35', '85', 'e2', 'f9', '37', 'e8', '1c', '75', 'df', '6e'],
        ['47', 'f1', '1a', '71', '1d', '29', 'c5', '89', '6f', 'b7', '62', '0e', 'aa', '18', 'be', '1b'],
        ['fc', '56', '3e', '4b', 'c6', 'd2', '79', '20', '9a', 'db', 'c0', 'fe', '78', 'cd', '5a', 'f4'],
        ['1f', 'dd', 'a8', '33', '88', '07', 'c7', '31', 'b1', '12', '10', '59', '27', '80', 'ec', '5f'],
        ['60', '51', '7f', 'a9', '19', 'b5', '4a', '0d', '2d', 'e5', '7a', '9f', '93', 'c9', '9c', 'ef'],
        ['a0', 'e0', '3b', '4d', 'ae', '2a', 'f5', 'b0', 'c8', 'eb', 'bb', '3c', '83', '53', '99', '61'],
        ['17', '2b', '04', '7e', 'ba', '77', 'd6', '26', 'e1', '69', '14', '63', '55', '21', '0c', '7d']
        ]

rcon = [
        '01000000', '02000000', '04000000', '08000000', '10000000', '20000000', '40000000', '80000000', '1b000000', '36000000'
        ]


#Utility#

def hex_to_bin(s: str) -> str:
    hex_to_bin_map = {
        '0': "0000",
        '1': "0001",
        '2': "0010",
        '3': "0011",
        '4': "0100",
        '5': "0101",
        '6': "0110",
        '7': "0111",
        '8': "1000",
        '9': "1001",
        'A': "1010",
        'B': "1011",
        'C': "1100",
        'D': "1101",
        'E': "1110",
        'F': "1111"
    }
    binary_string = ""
    for char in s:
        binary_string += hex_to_bin_map[char]
    return binary_string

	
def bin_to_hex(s: str) -> str:
    bin_to_hex_map = {
        "0000": '0',
        "0001": '1',
        "0010": '2',
        "0011": '3',
        "0100": '4',
        "0101": '5',
        "0110": '6',
        "0111": '7',
        "1000": '8',
        "1001": '9',
        "1010": 'A',
        "1011": 'B',
        "1100": 'C',
        "1101": 'D',
        "1110": 'E',
        "1111": 'F'
    }
    hex_string = ""
    for i in range(0, len(s), 4):
        chunk = ""
        chunk += s[i]
        chunk += s[i + 1]
        chunk += s[i + 2]
        chunk += s[i + 3]
        hex_string += bin_to_hex_map[chunk]
        
    return hex_string


def xor(a: str, b: str) -> str:
    result = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            result += "0"
        else:
            result += "1"
    return result


def cipher_block_chaining(vector: str, block: str) -> str:
    vector = hex_to_bin(vector)
    block = hex_to_bin(block)
    xor_result = xor(vector, block)
    xor_result = bin_to_hex(xor_result)
    return xor_result


def rotate(lst: list) -> list:
    tmp = lst[0]
    lst.pop(0)
    lst.append(tmp)
    return lst


def rotate_inverse(lst: list) -> list:
    lst1 = [lst[3]]
    lst.pop(3)
    lst1.extend(lst)
    return lst1


def galois_field_multiplication(a: int, b: int) -> int:
    p = 0
    hi_bit_set = 0

    for _ in range(8):
        if b & 1 == 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set == 0x80:
            a ^= 0x1b
        b >>= 1

    return p % 256


def print_hex(val: int) -> str:
    return '{:02x}'.format(val)

#Key Generation#

def key_generation(key: str) -> List[str]:
    words = []
    keys = [key]
    for i in range(10):
        key = keys[i]
        while len(key) > 4:
            w = key[:8]
            key = key[8:]
            words.append(w)

        gw = g_function(words[3], i)

        result = bin_to_hex(xor(hex_to_bin(gw.upper()), hex_to_bin(words[0].upper()))).lower()
        tmp = result

        for i in range(1, 4):
            tmp = bin_to_hex(xor(hex_to_bin(words[i].upper()), hex_to_bin(tmp.upper()))).lower()
            result += tmp

        keys.append(result)
        words.clear()
    return keys


def g_function(column: str, cont: int) -> str:
    total = ''
    columns = []

    while len(column) > 0:
        tmp = column[:2]
        column = column[2:]
        columns.append(tmp)

    columns = rotate(columns)
    columns = g_substitution(columns)

    for i in columns:
        total += i
    column = bin_to_hex(xor(hex_to_bin(total.upper()), hex_to_bin(rcon[cont].upper()))).lower()

    return column

def g_substitution(lst: List[str]) -> List[str]:
    chars = {'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}

    for e in range(4):
        i = lst[e][:1]
        j = lst[e][1:]

        if i in chars:
            i = chars[i]
        if j in chars:
            j = chars[j]

        i = int(i)
        j = int(j)
        lst[e] = SBOX[i][j]

    return lst


#Ciphering#

def boxing(plaintext: str) -> List[List[str]]:
    hexlist = []
    perlist = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15]
    ]
    pbox = [[], [], [], []]

    while len(plaintext) > 0:
        block = plaintext[:2]
        plaintext = plaintext[2:]
        hexlist.append(block)

    for c in perlist:
        for i in c:
            pbox[perlist.index(c)].append(hexlist[i])

    return pbox


def substitution(pbox: List[List[str]]) -> List[List[str]]:
    chars = {'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}

    for lst in pbox:
        for element in range(4):
            i = lst[element][:1]
            j = lst[element][1:]

            if i in chars:
                i = chars[i]
            if j in chars:
                j = chars[j]

            i = int(i)
            j = int(j)

            lst[element] = SBOX[i][j]
    return pbox

def substitution_inverse(pbox: List[List[str]]) -> List[List[str]]:
    chars = {'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}

    for lst in pbox:
        for element in range(4):
            i = lst[element][:1]
            j = lst[element][1:]

            if i in chars:
                i = chars[i]
            if j in chars:
                j = chars[j]

            i = int(i)
            j = int(j)

            lst[element] = SBOX_INVERSE[i][j]
    return pbox

def shift_rows(pbox: List[List[str]]) -> List[List[str]]:
    for i in range(1, 4):
        for f in range(i):
            pbox[i] = rotate(pbox[i])
    return pbox


def shift_rows_inverse(pbox: List[List[str]]) -> List[List[str]]:
    for i in range(1, 4):
        for f in range(i):
            pbox[i] = rotate_inverse(pbox[i])
    return pbox

def mix_columns(pbox: List[List[str]]) -> List[List[str]]:
    columns = [[], [], [], []]
    t = ''

    for i in pbox:
        for f in range(4):
            columns[f].append(pbox[pbox.index(i)][f])

    for f in range(4):
        a = int(columns[f][0], 16)
        b = int(columns[f][1], 16)
        c = int(columns[f][2], 16)
        d = int(columns[f][3], 16)

        t += print_hex(
            galois_field_multiplication(a, 2) ^ galois_field_multiplication(b, 3) ^ galois_field_multiplication(c, 1) ^ galois_field_multiplication(d, 1)
        )
        t += print_hex(
            galois_field_multiplication(a, 1) ^ galois_field_multiplication(b, 2) ^ galois_field_multiplication(c, 3) ^ galois_field_multiplication(d, 1)
        )
        t += print_hex(
            galois_field_multiplication(a, 1) ^ galois_field_multiplication(b, 1) ^ galois_field_multiplication(c, 2) ^ galois_field_multiplication(d, 3)
        )
        t += print_hex(
            galois_field_multiplication(a, 3) ^ galois_field_multiplication(b, 1) ^ galois_field_multiplication(c, 1) ^ galois_field_multiplication(d, 2)
        )

    return boxing(t)


def mix_columns_inverse(pbox: List[List[str]]) -> List[List[str]]:
    columns = [[], [], [], []]
    t = ''

    for i in pbox:
        for f in range(4):
            columns[f].append(pbox[pbox.index(i)][f])

    for f in range(4):
        a = int(columns[f][0], 16)
        b = int(columns[f][1], 16)
        c = int(columns[f][2], 16)
        d = int(columns[f][3], 16)

        t += print_hex(
            galois_field_multiplication(a, int('0e', 16)) ^ galois_field_multiplication(b, int('0b', 16)) ^ galois_field_multiplication(c, int('0d', 16)) ^ galois_field_multiplication(d, int('09', 16))
        )
        t += print_hex(
            galois_field_multiplication(a, int('09', 16)) ^ galois_field_multiplication(b, int('0e', 16)) ^ galois_field_multiplication(c, int('0b', 16)) ^ galois_field_multiplication(d, int('0d', 16))
        )
        t += print_hex(
            galois_field_multiplication(a, int('0d', 16)) ^ galois_field_multiplication(b, int('09', 16)) ^ galois_field_multiplication(c, int('0e', 16)) ^ galois_field_multiplication(d, int('0b', 16))
        )
        t += print_hex(
            galois_field_multiplication(a, int('0b', 16)) ^ galois_field_multiplication(b, int('0d', 16)) ^ galois_field_multiplication(c, int('09', 16)) ^ galois_field_multiplication(d, int('0e', 16))
        )

    return boxing(t)

def add_key(plaintext: str, key: str) -> str:
    text = bin_to_hex(xor(hex_to_bin(plaintext.upper()), hex_to_bin(key.upper())))
    return text

#Macro-fuctions#

def encrypt_block(plaintext: str, keys: List[str]) -> str:
    tmp = ''
    tmp1 = ''
    tmp2 = ''
    tmp3 = ''
    plaintext = add_key(plaintext, keys[0]).lower()

    for i in range(1, 10):
        pbox = boxing(plaintext)
        pbox = substitution(pbox)
        pbox = shift_rows(pbox)
        pbox = mix_columns(pbox)

        plaintext = ''

        for b in range(4):
            tmp = pbox[0][b]
            tmp1 = pbox[1][b]
            tmp2 = pbox[2][b]
            tmp3 = pbox[3][b]
            plaintext += tmp + tmp1 + tmp2 + tmp3

        plaintext = add_key(plaintext, keys[i]).lower()

    pbox = boxing(plaintext)
    pbox = substitution(pbox)
    pbox = shift_rows(pbox)
    plaintext = ''

    for b in range(4):
        tmp = pbox[0][b]
        tmp1 = pbox[1][b]
        tmp2 = pbox[2][b]
        tmp3 = pbox[3][b]
        plaintext += tmp + tmp1 + tmp2 + tmp3

    plaintext = add_key(plaintext, keys[10]).lower()

    return plaintext

def decrypt_block(cipher: str, revkeys: List[str]) -> str:
    tmp = ''
    tmp1 = ''
    tmp2 = ''
    tmp3 = ''
    cipher = add_key(cipher, revkeys[0]).lower()

    for i in range(1, 10):
        pbox = boxing(cipher)
        pbox = substitution_inverse(pbox)
        pbox = shift_rows_inverse(pbox)
        pbox = mix_columns_inverse(pbox)
        cipher = ''
        invkey = ''

        for b in range(4):
            tmp = pbox[0][b]
            tmp1 = pbox[1][b]
            tmp2 = pbox[2][b]
            tmp3 = pbox[3][b]
            cipher += tmp + tmp1 + tmp2 + tmp3

        kbox = boxing(revkeys[i])
        kbox = mix_columns_inverse(kbox)

        for b in range(4):
            tmp = kbox[0][b]
            tmp1 = kbox[1][b]
            tmp2 = kbox[2][b]
            tmp3 = kbox[3][b]
            invkey += tmp + tmp1 + tmp2 + tmp3

        cipher = add_key(cipher, invkey).lower()

    pbox = boxing(cipher)
    pbox = substitution_inverse(pbox)
    pbox = shift_rows_inverse(pbox)

    cipher = ''

    for b in range(4):
        tmp = pbox[0][b]
        tmp1 = pbox[1][b]
        tmp2 = pbox[2][b]
        tmp3 = pbox[3][b]
        cipher += tmp + tmp1 + tmp2 + tmp3

    cipher = add_key(cipher, revkeys[10]).lower()
    return cipher

def encrypt(plain_text: str, key: str) -> str:
    key = key[:16]
    key = key.encode('utf-8').hex().lower()
    keys = key_generation(key)
    counter = 0
    cipher_text = ''
    plain_text = plain_text.encode('utf-8').hex().upper()

    if len(plain_text) < 32:
        padding_length = 32 - len(plain_text)
        plain_text += '0' * padding_length
        plain_text = cipher_block_chaining(INITIALIZATION_VECTOR, plain_text)
        plain_text = encrypt_block(plain_text, keys)
        cipher_text += plain_text

    else:
        while len(plain_text) > 32:
            counter += 1
            block = plain_text[:32]
            plain_text = plain_text[32:]
            if counter != 1:
                block = cipher_block_chaining(old.upper(), block.upper()).lower()
            else:
                block = cipher_block_chaining(INITIALIZATION_VECTOR, block.upper()).lower()
            old = encrypt_block(block, keys)
            cipher_text += old

        if len(plain_text) < 32:
            padding_length = 32 - len(plain_text)
            plain_text += '0' * padding_length
            plain_text = cipher_block_chaining(old.upper(), plain_text.upper()).lower()
            old = encrypt_block(plain_text, keys)
            cipher_text += old
        elif len(plain_text) == 32:
            plain_text = cipher_block_chaining(old.upper(), plain_text.upper()).lower()
            old = encrypt_block(plain_text, keys)
            cipher_text += old

    return cipher_text

def decrypt(cipher_text: str, key: str) -> str:
    key = key[:16]
    key = key.encode('utf-8').hex().lower()
    keys = key_generation(key)
    reversed_keys = keys[::-1]
    counter = 0
    text = ''

    if len(cipher_text) == 32:
        cipher_text = decrypt_block(cipher_text, reversed_keys)
        cipher_text = cipher_block_chaining(INITIALIZATION_VECTOR, cipher_text.upper()).lower()
        text += cipher_text

    else:
        while len(cipher_text) > 32:
            counter += 1
            block = cipher_text[:32]
            cipher_text = cipher_text[32:]
            decrypted_block = decrypt_block(block, reversed_keys)
            if counter != 1:
                decrypted_block = cipher_block_chaining(old.upper(), decrypted_block.upper()).lower()
            else:
                decrypted_block = cipher_block_chaining(INITIALIZATION_VECTOR, decrypted_block.upper()).lower()
            old = block
            text += decrypted_block

        last_block = decrypt_block(cipher_text, reversed_keys)
        last_block = cipher_block_chaining(block.upper(), last_block.upper()).lower()
        text += last_block

    return text

  


