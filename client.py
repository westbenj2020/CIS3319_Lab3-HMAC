#!/usr/bin/env python3

import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac


HOST = '127.0.0.1'  # The server socket's hostname or IP address
PORT = 65432        # The port used by the server socket
BLOCK_SIZE = 32

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # references created server socket
    s.connect((HOST, PORT))  # connects to server socket
    with open('encryptionKey.txt') as key:
        hmacFile = open('hmacKey.txt')
        hmacKey = hmacFile.read(6)
        string = key.read(8)
        string1 = string
        cipher = DES.new(string.encode('utf-8'), DES.MODE_ECB)
        plaintext1 = input('\nType message:\n\n')  # retrieves plaintext input from user
        msgAuth = hmac.new(hmacKey, plaintext1, hashlib.sha256)
        stringer = msgAuth.hexdigest()
        msgWithHMAC = stringer + plaintext1.decode()
        msgWithHMACEncoded = msgWithHMAC.encode('utf-8')
        print('\n--- Sender side ---\n')
        msg = cipher.encrypt(pad(msgWithHMACEncoded, BLOCK_SIZE))  # encrypts plaintext
        s.sendall(msg)  # sends encrypted message to server
        print('Shared DES key is: {}'.format(string1))
        print('Shared HMAC key is: {}'.format(hmacKey))
        print('plain message is: {}'.format(plaintext1))
        print('sent ciphertext is: {}\n******************'.format(msg.decode('utf-8', 'ignore')))
        cipher1 = DES.new(string1.encode('utf-8'), DES.MODE_ECB)
        data = s.recv(64)  # receives data from server socket - 1024 byte limit
        decryptedData = cipher1.decrypt(data)  # stores decoded byte data as string
        unpad(decryptedData, BLOCK_SIZE)
        decodedData = decryptedData.decode('utf-8').strip()
        print('\n******************')
        print('received ciphertext is: {}'.format(data.decode('utf-8', 'ignore')))  # prints decoded byte data
        print('received plaintext is: {}'.format(decodedData))
        print('******************')