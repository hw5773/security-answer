from ecdsa import SigningKey, VerifyingKey, NIST256p
import socket
import threading
import argparse
import logging
import random
import base64
import os
import sys
import hashlib
from etc import generate_messages

# ecdca signing key * string
# -> mlen (2 bytes, big-endian) || ASCII-encoded msg || Base64-encoded signature
def sign(private, msg):
    signature = private.sign(msg.encode(), hashfunc=hashlib.sha256)
    sig = base64.b64encode(signature)
    ret = int.to_bytes(len(msg), 2, "big")
    ret += msg.encode()
    ret += sig
    return ret

# ecdsa verifying key * (mlen (2 bytes, big-endian) || ASCII-encoded msg || Base64-encoded signature) 
# -> verified (true / false)
def verify(public, signature, msg):
    return verified

def handler(alice, bob_priv, alice_pub):
    challenges = generate_messages()
    rand = int(random.random() * len(challenges))
    challenge = challenges[rand]
    signed = sign(bob_priv, challenge)
    alice.send(signed.encode())
    logging.info("[*] Challenge: {}".format(challenge))
    logging.info("[*] Signed: {}".format(signed))
    signed = alice.recv(1024).decode()
    logging.info("[*] Received: {}".format(encrypted))
    verified, message = verify(private, signed)
    if verified:
        logging.info("[*] Success ({})!".format(message))
        result = "success"
    else:
        logging.info("[*] Failure!")
        result = "failure"
    alice.send(result.encode())
    alice.close()

def run(addr, port, bob_priv, alice_pub):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, bob_priv, alice_pub))
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
        alice_pub = VerifyingKey.from_pem(open(args.key, "rb").read())
    except:
        logging.error("Loading the Alice's public key error. Please check it and try again")
        sys.exit(1)

    try:
        bob_priv = SigningKey.from_pem(open(args.private, "rb").read())
    except:
        logging.error("Loading the Bob's private key error. Please check it and try again")
        sys.exit(1)

    run(args.addr, args.port, bob_priv, alice_pub)

if __name__ == "__main__":
    main()
