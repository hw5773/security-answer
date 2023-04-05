import socket
import threading
import argparse
import logging

def decrypt(key, encrypted):
    decrypted = ""
    for i in range(len(encrypted)):
        decrypted += chr(ord(key[i])^ord(encrypted[i]))
    return decrypted

def handler(alice, key):
    encrypted = alice.recv(1024).decode()
    decrypted = decrypt(key, encrypted)
    logging.info("[*] Received: {}".format(decrypted))

    alice.close()

def run(addr, port, key):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, key,))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-k", "--key", metavar="<otp key>", help="OTP key", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.key)

if __name__ == "__main__":
    main()
