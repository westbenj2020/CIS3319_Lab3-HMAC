#!/usr/bin/env python3

import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

HOST = '127.0.0.1'  # IP address for server socket
PORT = 65432  # port for server socket
BLOCK_SIZE = 32

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # creates server socket
    s.bind((HOST, PORT))  # binds server socket to address
    s.listen()  # enables server socket to accept attempted connection from client socket
    print('\nServer is running...')
    print('\nAccepted new connection from "{}"...'.format(HOST))
    client, addr = s.accept()  # accepts connection - returns new socket object and address bound to client socket
    with client:
        hmacFile = open('hmacKey.txt')
        hmacKey = hmacFile.read(6)
        with open('encryptionKey.txt') as key:
            string = key.read(8)
            string1 = string
            cipher = DES.new(string.encode('utf-8'), DES.MODE_ECB)
            data = client.recv(64)
            receivedMsg = cipher.decrypt(data)
            unpad(receivedMsg, BLOCK_SIZE)
            decodedMsg = receivedMsg.decode('utf-8').strip()
            #  split into message and hmac and carry out lab 3 processes
            print('\n******************')
            print('received ciphertext is: {}'.format(data.decode('utf-8', 'ignore')))
            print('received plaintext is: {}'.format(decodedMsg))
            print('******************')
            plaintext1 = input('\nType message:\n\n')  # retrieves plaintext input from user
            print('\nHi, this is server.')
            print('******************')
            plaintext1Encoded = plaintext1.encode('utf-8')
            cipher1 = DES.new(string1.encode('utf-8'), DES.MODE_ECB)
            msg = cipher1.encrypt(pad(plaintext1Encoded, BLOCK_SIZE))
            print('key is: "{}"'.format(string1))
            client.sendall(msg)  # sends encrypted message to server
            print('Sent plaintext is: {}'.format(plaintext1))
            print('Sent ciphertext is: {}'.format(msg.decode('utf-8', 'ignore')))
            print('******************')