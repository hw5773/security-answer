import tinyec.ec as ec
import tinyec.registry as reg
import secrets
import argparse
import logging
import sys

def generate_ecc_keypair(c):
    private_key = secrets.randbelow(c.field.n)
    public_key = private_key * c.g
    return private_key, public_key

def run(c):
    keypair = generate_ecc_keypair(c)
    logging.info("private key: {}".format(keypair[0]))
    logging.info("public key: {}".format(keypair[1]))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", metavar="<name of the elliptic curve>", help="Name of the EC to be used", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    try:
        c = reg.get_curve(args.name)
    except:
        logging.error("[*] error in initiating an EC with the name: {}".format(args.name))
        logging.error("[*] please retry the program with a correct name")
        sys.exit(1)

    run(c)

if __name__ == "__main__":
    main()
