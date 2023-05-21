from ecdsa import VerifyingKey, NIST256p
import argparse
import logging
import sys
import json
import base64
import random
import os
import hashlib

# verify
#     param: the name of the issuer
#     tbv: the dictionary
# 1) dump the dictionary to the JSON object
# 2) encode the JSON object based on the ASCII code
# 3) decode the base64-encoded signature
# 4) verify the signature over the ASCII-encoded JSON object (hashed by SHA-256 internally)
def verify(issuer, signature, tbv):
    try:
        with open("{}.crt".format(issuer), "r") as f:
            c = f.read()
            cert = json.loads(c)
            vk = VerifyingKey.from_pem(cert["public key"].encode())
    except:
        logging.error("error in loading the public key")
    js = json.dumps(tbv)

    logging.info("signature: {}".format(signature))
    sig = base64.b64decode(signature.encode())
    try:
        verified = vk.verify(sig, js.encode(), hashfunc=hashlib.sha256)
    except:
        verified = False
    return verified

def run(cfile):
    with open(cfile, "r") as f:
        c = f.read()

    cert = json.loads(c)

    tbv = {}
    tbv["subject"] = cert["subject"]
    tbv["issuer"] = cert["issuer"]
    tbv["serial"] = cert["serial"]
    tbv["not before"] = cert["not before"]
    tbv["not after"] = cert["not after"]
    tbv["public key"] = cert["public key"]

    verified = verify(cert["issuer"], cert["signature"], tbv)

    logging.info("Verified: {}".format(verified))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cert", metavar="<certificate file name>", help="Certificate file name", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    random.seed()

    run(args.cert)
    
if __name__ == "__main__":
    main()
