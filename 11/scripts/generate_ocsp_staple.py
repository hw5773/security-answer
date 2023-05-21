from ecdsa import SigningKey, NIST256p
import argparse
import logging
import sys
import os
import json
import base64
import random
import time
import hashlib

# sign
#     param: the name of the issuer
#     tbs: the dictionary
# 1) dump the dictionary to the JSON object
# 2) encode the JSON object based on the ASCII code
# 3) generate a signature over the ASCII-encoded JSON object
# 4) apply base64 encoding to the signature
def sign(issuer, tbs):
    try:
        with open("{}.key".format(issuer), "rb") as f:
            sk = SigningKey.from_pem(f.read())
    except:
        logging.error("Error in loading the issuer's private key")
        sys.exit(1)
    js = json.dumps(tbs)
    signature = sk.sign(js.encode(), hashfunc=hashlib.sha256)
    sig = base64.b64encode(signature).decode()
    logging.info("signature: {}".format(sig))
    return sig

def run(subject, issuer):
    curr = int(time.time())
    ocsp = {}
    with open("{}.crt".format(subject), "r") as f:
        cert = json.loads(f.read())
    ocsp["serial"] = cert["serial"]
    ocsp["issuer"] = issuer
    ocsp["status"] = "good"
    ocsp["not before"] = curr
    ocsp["not after"] = curr + 86400 * 2
    
    signature = sign(issuer, ocsp)

    ocsp["signature"] = signature

    with open("{}.ocsp".format(subject), "w") as f:
        js = json.dumps(ocsp)
        f.write(js)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--subject", metavar="<certificate's subject>", help="Certificate's subject", type=str, required=True)
    parser.add_argument("-i", "--issuer", metavar="<issuer name>", help="Issuer name", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    random.seed()

    run(args.subject, args.issuer)
    
if __name__ == "__main__":
    main()
