import socket
import threading
import argparse
import logging
import random
import base64
from etc import generate_messages
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def decrypt(key, iv, encrypted):
    aes = AES.new(key.encode(), AES.MODE_OFB, iv.encode())
    decrypted = aes.decrypt(base64.b64decode(encrypted)).decode()
    decrypted = decrypted[0:-ord(decrypted[-1])]
    return decrypted

def handler(alice, key, iv):
    challenges = generate_messages()
    rand = int(random.random() * len(challenges))
    challenge = challenges[rand]
    alice.send(challenge.encode())
    logging.info("[*] Challenge: {}".format(challenge))
    encrypted = alice.recv(1024).decode()
    logging.info("[*] Received: {}".format(encrypted))
    decrypted = decrypt(key, iv, encrypted)
    logging.info("[*] Plaintext: {}".format(decrypted))
    if challenge == decrypted and challenge != encrypted:
        logging.info("[*] Success!")
        result = "success"
    else:
        logging.info("[*] Failure!")
        result = "failure"
    alice.send(result.encode())
    alice.close()

def run(addr, port, key, iv):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, key, iv))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-k", "--key", metavar="<shared key>", help="shared key", type=str, required=True)
    parser.add_argument("-i", "--iv", metavar="<initialization vector>", help="initialization vector", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.key, args.iv)

if __name__ == "__main__":
    main()
