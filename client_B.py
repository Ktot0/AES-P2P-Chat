import socket
from random import randint
import hashlib
import key_generator as kg
import RSA
import AES
import re
import threading
import sys

def import_k() -> int:
    global x_b
    global q
    global alpha
    kg.generate("b")
    tmp = ''
    with open("qalpha", "r") as f:
        for line in f:
            tmp += line
        tmp = tmp.split(",")
        q = int(tmp[0])
        alpha = int(tmp[1])
    x_b = randint(1, q - 1)
    return pow(alpha, x_b, q)

def client_thread(s) -> None:
    while True:
        str_recv = s.recv(1024)
        if not str_recv:
            continue
        else:
            str_recv = AES.decrypt(str_recv.decode("utf-8"), str(K))
            print("\r<A>: " + bytes.fromhex(str_recv).decode('utf-8') + "\n<Tu>: ", end='')


if __name__ == "__main__":
    print("Client B")
    y_b = import_k()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 3333))
    str_recv = s.recv(1024)
    y_a = int(str_recv.decode("utf-8"))
    K = pow(y_a, x_b, q)
    digest = hashlib.md5(bytes(str(y_a + y_b), "utf-8")).hexdigest()
    sig_res = RSA.sign_encrypt(int(digest, 16), "b", "a")
    aes_res = AES.encrypt(str(sig_res), str(K))

    s.send(bytes(str(y_b), 'utf-8'))
    s.send(bytes(str(aes_res), 'utf-8'))
    str_recv = s.recv(1024)

    a_aes_res = str_recv.decode("utf-8")
    a_sig_res = bytes.fromhex(AES.decrypt(str(a_aes_res), str(K))).decode('utf-8')
    a_digest = hex(int(RSA.sign_decrypt(re.sub('[^0-9]', '', a_sig_res), "b", "a"))).split('x')[-1].lower()
    print("A Key: " + str(y_a))
    print("B Key: " + str(y_b))
    print("Session Key: " + str(K))
    if digest == a_digest:
        print("Connection Established")
    else:
        print("Authentication Error")
        s.close()
        quit()

    th = threading.Thread(target=client_thread, args=(s,))
    th.start()
    while True:
        msg = input("<You>: ")
        msg = AES.encrypt(msg, str(K))
        s.send(bytes(msg, "utf-8"))
