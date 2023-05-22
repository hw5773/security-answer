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
    logging.info("tbs: {}".format(js))
    signature = sk.sign(js.encode(), hashfunc=hashlib.sha256)
    sig = base64.b64encode(signature).decode()
    logging.info("signature: {}".format(sig))
    return sig

def run(issuer, rfile):
    curr = int(time.time())
    crl = {}
    crl["issuer"] = issuer
    crl["this update date"] = curr - 86400
    crl["next update date"] = curr + 86400 * 6
    
    lst = []
    num = 0
    with open(rfile, "r") as f:
        for line in f:
            s, rdate = line.strip().split(", ")
            serial = int(s)
            rcert = {}
            rcert["serial"] = serial
            rcert["revocation date"] = rdate
            lst.append(rcert)

    crl["revoked certificates"] = lst

    signature = sign(issuer, crl)

    crl["signature"] = signature

    with open("{}.crl".format(issuer), "w") as f:
        js = json.dumps(crl)
        f.write(js)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--issuer", metavar="<issuer name>", help="Issuer name", type=str, required=True)
    parser.add_argument("-r", "--revoked", metavar="<revoked certificates (serials)>", help="Revoked certificates (serials)", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if not os.path.exists(args.revoked):
        logging.error("[*] File that contains a list of revoked certificates (serials) does not exist: {}".format(args.revoked))
        sys.exit(1)

    random.seed()

    run(args.issuer, args.revoked)
    
if __name__ == "__main__":
    main()
