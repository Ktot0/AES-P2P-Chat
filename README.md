# AES-P2P-Chat
A peer-to-peer secure chat developed as a proof of concept for a Network Security course, employing the **AES-CBC** encryption algorithm and the **Diffie-Hellman** key exchange protocol over a socket. The implementation was crafted from scratch using Python, featuring a **q Generator**, a **Miller-Rabin Primality Test**, an implementation of **RSA**, an implementation of **AES**, an **AES key generator**, and two **Clients**. The code has no comments, but I tried to stay as pythonic as possible.

## To Do

* Better error handling for disconnections, long messages, and used sockets.
* Single client for bidirectional connection.
* Block Empty messages.

## Usage
1. Make sure to insert your Initialization Vector in the AES.py file and your custom ports in client_A.py and client_B.py if necessary.
2. Launch qalpha_generator
3. Launch client_A
4. Launch client_B
5. Confirm whether the connection has been established and initiate the exchange of messages.

## PoC
When using Wireshark to analyze loopback traffic, it is possible to confirm that the messages exchanged over TCP are encrypted.
