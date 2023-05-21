import socket
import threading
import argparse
import logging
import random
import base64
import os
import sys
from etc import generate_messages
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

BLOCK_SIZE = 16

def encrypt(key, msg):
    rsa = PKCS1_OAEP.new(key)
    encrypted = base64.b64encode(rsa.encrypt(msg.encode())).decode()
    return encrypted

def decrypt(private, encrypted):
    rsa = PKCS1_OAEP.new(private)
    decrypted = rsa.decrypt(base64.b64decode(encrypted)).decode()
    return decrypted

def handler(alice, key, private, public):
    challenges = generate_messages()
    rand = int(random.random() * len(challenges))
    challenge = challenges[rand]
    encrypted = encrypt(key, challenge)
    alice.send(encrypted.encode())
    logging.info("[*] Challenge: {}".format(challenge))
    encrypted = alice.recv(1024).decode()
    logging.info("[*] Received: {}".format(encrypted))
    decrypted = decrypt(private, encrypted)
    logging.info("[*] Plaintext: {}".format(decrypted))
    if challenge == decrypted and challenge != encrypted:
        logging.info("[*] Success!")
        result = "success"
    else:
        logging.info("[*] Failure!")
        result = "failure"
    alice.send(result.encode())
    alice.close()

def run(addr, port, key, private, public):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, key, private, public))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-x", "--private", metavar="<bob's private key>", help="Bob's private key", type=str, required=True)
    parser.add_argument("-y", "--public", metavar="<bob's public key>", help="Bob's public key", type=str, required=True)
    parser.add_argument("-k", "--key", metavar="<alice's public key>", help="Alice's public key", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if not os.path.exists(args.key):
        logging.error("Alice's public key file does not exist: {}".format(args.key))
        sys.exit(1)

    if not os.path.exists(args.private):
        logging.error("Bob's private key file does not exist: {}".format(args.private))
        sys.exist(1)

    if not os.path.exists(args.public):
        logging.error("Bob's public key file does not exist: {}".format(args.public))
        sys.exit(1)

    try:
        key = RSA.import_key(open(args.key).read())
    except:
        logging.error("Loading the Alice's public key error. Please check it and try again")
        sys.exit(1)

    try:
        private = RSA.import_key(open(args.private).read())
    except:
        logging.error("Loading the Bob's private key error. Please check it and try again")
        sys.exit(1)

    try:
        public = RSA.import_key(open(args.public).read())
    except:
        logging.error("Loading the Bob's public key error. Please check it and try again")
        sys.exit(1)

    run(args.addr, args.port, key, private, public)

if __name__ == "__main__":
    main()
