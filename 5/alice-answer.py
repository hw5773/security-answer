import socket
import argparse
import logging
import random
from etc import generate_messages, generate_c2i_mapper, generate_i2c_mapper

def encrypt(key, msg, c2i, i2c):
    encrypted = ""
    for c in msg:
        encrypted += i2c[(c2i[c] + key) % 26]
    return encrypted

def run(addr, port, msg, key, c2i, i2c):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    logging.info("[*] Message: {}".format(msg))
    encrypted = encrypt(key, msg, c2i, i2c)
    alice.send(encrypted.encode())

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-k", "--key", metavar="<shift cipher key>", help="shift cipher key", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    msgs = generate_messages()
    c2i = generate_c2i_mapper()
    i2c = generate_i2c_mapper()
    r = int(random.random() * 10)
    msg = msgs[r]
    run(args.addr, args.port, msg, args.key, c2i, i2c)
    
if __name__ == "__main__":
    main()
