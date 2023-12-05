import socket
from random import randint
import hashlib
import key_generator as kg
import RSA
import AES
import re
import threading
import sys

def import_key() -> int:
    global x_a
    global q
    global alpha
    kg.generate("a")
    tmp = ''
    with open("qalpha", "r") as f:
        for line in f:
            tmp += line
        tmp = tmp.split(",")
        q = int(tmp[0])
        alpha = int(tmp[1])
    x_a = randint(1, q - 1)
    return pow(alpha, x_a, q)

def exchange(connect, addr) -> None:
    global K
    RSA.load_key("a", "b")
    connect.sendto(bytes(str(y_a), 'utf-8'), addr)
    str_recv, temp = connect.recvfrom(1024)  
    y_b = int(str_recv.decode("utf-8"))
    K = pow(y_b, x_a, q)
    digest = hashlib.md5(bytes(str(y_a + y_b), "utf-8")).hexdigest()
    sig_res = RSA.sign_encrypt(int(digest, 16), "a", "b")
    aes_res = AES.encrypt(str(sig_res), str(K))
    
    str_recv, temp = connect.recvfrom(1024)
    connect.sendto(bytes(str(aes_res), 'utf-8'), addr)
    
    b_aes_res = str_recv.decode("utf-8")
    b_sig_res = bytes.fromhex(AES.decrypt(str(b_aes_res), str(K))).decode('utf-8')
    b_digest = hex(int(RSA.sign_decrypt(re.sub('[^0-9]', '', b_sig_res), "a", "b"))).split('x')[-1].lower()
    print("A Key: " + str(y_a))
    print("B Key: " + str(y_b))
    print("Session Key: " + str(K))
    if digest == b_digest:
        print("Connection Established")
    else:
        print("Authentication Error")
        connect.close()

def client_thread(connect) -> None:
    while True:
        str_recv, temp = connect.recvfrom(1024)
        if not str_recv:
            continue
        else:
            str_recv = AES.decrypt(str_recv.decode("utf-8"), str(K))
            print("\r<B>: " + bytes.fromhex(str_recv).decode('utf-8') + "\n<You>: ", end='')


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 3333))
    s.listen(5)
    flag = 0

    y_a = import_key()

    print("Client A")
    connect, addr = s.accept()
    exchange(connect, addr)
    th = threading.Thread(target=client_thread, args=(connect,))
    th.start()

    while True:
        msg = input("<You>: ")
        msg = AES.encrypt(msg, str(K))
        connect.sendto(bytes(msg, 'utf-8'), addr)
