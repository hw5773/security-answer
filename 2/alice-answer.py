import socket
import argparse
import logging

def encrypt(key, msg):
    encrypted = ""
    for i in range(len(msg)):
        encrypted += chr(ord(key[i])^ord(msg[i]))
    return encrypted

def run(addr, port, msg, key):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    logging.info("[*] Message: {}".format(msg))
    encrypted = encrypt(key, msg)
    alice.send(encrypted.encode())

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message to be sent>", help="Message to be sent", type=str, required=True)
    parser.add_argument("-k", "--key", metavar="<otp key>", help="OTP key", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.message, args.key)
    
if __name__ == "__main__":
    main()
