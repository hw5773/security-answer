import socket
import argparse
import logging
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def encrypt(key, iv, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key.encode(), AES.MODE_OFB, iv.encode())
    encrypted = base64.b64encode(aes.encrypt(msg.encode())).decode()
    return encrypted

def run(addr, port, key, iv):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    challenge = alice.recv(1024).decode()
    logging.info("[*] Challenge: {}".format(challenge))
    encrypted = encrypt(key, iv, challenge)
    logging.info("[*] Ciphertext: {}".format(encrypted))
    alice.send(encrypted.encode())
    result = alice.recv(1024).decode()
    if result == "success":
        logging.info("[*] Success!")
    else:
        logging.info("[*] Failure!")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
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
