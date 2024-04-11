import socket
import argparse
import logging
import base64
import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# key * msg
# -> mlen (4 bytes) || msg || signature (base64 encoded)
def sign(key, msg):
    rsa = PKCS1_OAEP.new(key)
    signature = base64.b64encode(rsa.encrypt(msg.encode())).decode()
    signed = len(msg).
    return signed

# key * (mlen (4 bytes) || msg || signature)
# -> verified (true / false) * msg
def verify(private, encrypted):
    rsa = PKCS1_OAEP.new(private)
    decrypted = rsa.decrypt(base64.b64decode(encrypted)).decode()
    return decrypted

def run(addr, port, alice_private, alice_public, bob_public):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    received = alice.recv(1024).decode()
    logging.info("[*] Received: {}".format(received))
    verified, challenge = verify(bob_public, received)
    logging.info("[*] Challenge: {}".format(challenge))
    signed = sign(key, challenge)
    logging.info("[*] Signed: {}".format(signed))
    alice.send(signed.encode())
    result = alice.recv(1024).decode()
    if result == "success":
        logging.info("[*] Success!")
    else:
        logging.info("[*] Failure!")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-k", "--key", metavar="<bob's public key>", help="Bob's public key", type=str, required=True)
    parser.add_argument("-x", "--private", metavar="<alice's private key>", help="Alice's private key", type=str, required=True)
    parser.add_argument("-y", "--public", metavar="<alice's public key>", help="Alice's public key", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if not os.path.exists(args.key):
        logging.error("Bob's public key file does not exist: {}".format(args.key))
        sys.exit(1)

    if not os.path.exists(args.private):
        logging.error("Alice's private key file does not exist: {}".format(args.private))
        sys.exit(1)

    if not os.path.exists(args.public):
        logging.error("Alice's public key file does not exist: {}".format(args.public))
        sys.exit(1)

    try:
        key = RSA.import_key(open(args.key).read())
    except:
        logging.error("Loading the Bob's public key error. Please check it and try again")
        sys.exit(1)

    try:
        private = RSA.import_key(open(args.private).read())
    except:
        logging.error("Loading the Alice's private key error. Please check it and try again")
        sys.exit(1)

    try:
        public = RSA.import_key(open(args.public).read())
    except:
        logging.error("Loading the Alice's public key error. Please check it and try again")
        sys.exit(1)

    run(args.addr, args.port, key, private, public)
    
if __name__ == "__main__":
    main()
