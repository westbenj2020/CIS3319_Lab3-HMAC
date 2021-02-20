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
            dataHMAC = client.recv(64)
            dataHMACE = dataHMAC  # copy for encrypted print
            receivedHMAC = cipher.decrypt(dataHMAC)
            dataMessage = client.recv(1024)
            dataMessageE = dataMessage  # copy for encrypted print
            unpaddedDataMsg = unpad(cipher.decrypt(dataMessage), BLOCK_SIZE)
            decodedMsg = unpaddedDataMsg.decode('utf-8').strip()
            #  split into message and hmac and carry out lab 3 processes
            print('\n--- Receiver side ---')
            print('received ciphertext is: {}'.format(dataHMACE.decode('utf-8', 'ignore')) +
                  dataMessageE.decode('utf-8', 'ignore'))
            print('received message is: {}'.format(decodedMsg))
            print('received hmac is: {}'.format(receivedHMAC.decode()))
            msgAuth = hmac.new(hmacKey.encode(), decodedMsg.encode(), hashlib.sha256)
            stringer = msgAuth.hexdigest()
            print('calculated hmac is: {}'.format(stringer))
            if receivedHMAC.decode() == stringer:
                print('HMAC Verified')
            plaintext1 = input('\nType message:\n\n')  # retrieves plaintext input from user
            msgAuth2 = hmac.new(hmacKey.encode(), plaintext1.encode(), hashlib.sha256)
            stringer = msgAuth2.hexdigest()
            msgWithHMAC = stringer + plaintext1
            msgWithHMACEncoded = msgWithHMAC.encode('utf-8')
            print('\n--- Sender side ---')
            msg = cipher.encrypt(pad(msgWithHMACEncoded, BLOCK_SIZE))  # encrypts plaintext
            client.sendall(msg)  # sends encrypted message to server
            print('Shared DES key is: {}'.format(string1))
            print('Shared HMAC key is: {}'.format(hmacKey))
            print('plain message is: {}'.format(plaintext1))
            print('sender side HMAC is: {}'.format(msgAuth2.hexdigest()))
            print('sent ciphertext is: {}\n'.format(msg.decode('utf-8', 'ignore')))
            #  plaintext1Encoded = plaintext1.encode('utf-8')
            #  cipher1 = DES.new(string1.encode('utf-8'), DES.MODE_ECB)
            #  msg = cipher1.encrypt(pad(plaintext1Encoded, BLOCK_SIZE))
