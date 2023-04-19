import argparse
import logging
from Crypto.PublicKey import RSA

def run(prifname, pubfname):
    key = RSA.generate(2048)
    private_key = key.export_key()
    f = open(prifname, "wb")
    f.write(private_key)
    f.close()

    public_key = key.publickey().export_key()
    f = open(pubfname, "wb")
    f.write(public_key)
    f.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--private", metavar="<private key file name>", help="Private key file name", type=str, required=True)
    parser.add_argument("-p", "--public", metavar="<public key file name>", help="Public key file name", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.private, args.public)

if __name__ == "__main__":
    main()
