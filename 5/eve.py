import socket
import threading
import argparse
import logging
from etc import generate_c2i_mapper, generate_i2c_mapper

def brute_force(encrypted, c2i, i2c):
    for k in range(26):
        decrypted = ""
        for c in encrypted:
            decrypted += i2c[(c2i[c] - k) % 26]
        logging.info("key: {}, decrypted: {}".format(k, decrypted))

def handler(alice, c2i, i2c):
    encrypted = alice.recv(1024).decode()
    logging.info("[*] Received: {}".format(encrypted))
    brute_force(encrypted, c2i, i2c)

    alice.close()

def run(addr, port, c2i, i2c):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Eve is monitoring on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, c2i, i2c,))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<eve's IP address>", help="Eve's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<eve's open port>", help="Eve's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    c2i = generate_c2i_mapper()
    i2c = generate_i2c_mapper()

    run(args.addr, args.port, c2i, i2c)

if __name__ == "__main__":
    main()
