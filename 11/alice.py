import socket, argparse, logging
import os, sys
import hmac, hashlib
from Crypto.Cipher import AES

MAC_THEN_ENCRYPT = 0
ENCRYPT_THEN_MAC = 1

ENCKEY_LENGTH = 16  # AES-128
MAC_LENGTH = 32     # HMAC-SHA256
BLOCK_LENGTH = 16   # AES block size

# string * string * bytes -> bytes
def encrypt(key, iv, msg):
    pad = (BLOCK_LENGTH - len(msg)) % BLOCK_LENGTH
    msg = msg + pad * chr(pad).encode()
    aes = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    encrypted = aes.encrypt(msg)
    return encrypted

# string * bytes -> bytes
def calc_mac(key, msg):
    h = hmac.new(key.encode(), msg, hashlib.sha256)
    return h.digest()

# int * string * string * string * string -> bytes
def ae_encrypt(ae, enckey, mackey, iv, challenge):
    encrypted = None
    msg = challenge.encode()

    if ae == MAC_THEN_ENCRYPT:
        mac = calc_mac(mackey, msg)
        msg += mac
        encrypted = encrypt(enckey, iv, msg)
        return encrypted
    elif ae == ENCRYPT_THEN_MAC:
        encrypted = encrypt(enckey, iv, msg)
        mac = calc_mac(mackey, encrypted)
        return encrypted + mac

def run(addr, port, ae, enckey, mackey, iv):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    challenge = alice.recv(1024).decode()
    logging.info("[*] Challenge: {}".format(challenge))
    encrypted = ae_encrypt(ae, enckey, mackey, iv, challenge)
    logging.info("[*] Ciphertext: {}".format(encrypted))
    alice.send(encrypted)
    result = alice.recv(1024).decode()
    if result == "success":
        logging.info("[*] Success!")
    else:
        logging.info("[*] Failure!")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-w", "--ae", metavar="<authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)>", help="Authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)", type=int, choices=[0, 1], required=True)
    parser.add_argument("-x", "--enckey", metavar="<encryption key (AES-128)>", help="Encryption key (AES-128)", type=str, required=True)
    parser.add_argument("-y", "--mackey", metavar="<mac key (HMAC-SHA256)>", help="MAC key (HMAC-SHA256)", type=str, required=True)
    parser.add_argument("-z", "--iv", metavar="<initialization vector (16 byte)>", help="Initialization vector (16 byte)", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if len(args.enckey) != ENCKEY_LENGTH:
        logging.error("Encryption key length error (hint: AES-128): {} bytes".format(len(args.enckey)))
        sys.exit(1)

    if len(args.iv) != BLOCK_LENGTH:
        logging.error("IV length error (hint: AES)")
        sys.exit(1)

    run(args.addr, args.port, args.ae, args.enckey, args.mackey, args.iv)
    
if __name__ == "__main__":
    main()
