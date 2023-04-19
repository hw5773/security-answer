import argparse
import logging
from rsa import RSA

def run(klen, msg):
    rsa = RSA("rsa", klen)
    rsa.key_generation()
    rsa.print_keypair()
    ciph = rsa.encryption(msg)
    rsa.decryption(ciph)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--length", metavar="<rsa key length in bit>", help="RSA key length in bit", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("-m", "--message", metavar="<message to be encrypted>", help="Message to be encrypted", type=str, required=True)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.length, args.message)

if __name__ == "__main__":
    main()
