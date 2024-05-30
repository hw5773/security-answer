from ecdsa import SigningKey, VerifyingKey, NIST256p
import argparse
import logging
import sys
import os
import json
import base64
import random
import time
import hashlib

def verify_signature(signed, cert):
    ret = True
    reason = "success"

    if "signature" not in signed:
        ret = False
        reason = "no signature in signed"
    elif "public key" not in cert:
        ret = False
        reason = "no public key in cert"
    else:
        tbv = {}
        keys = list(signed.keys())
        keys.remove("signature")

        for k in keys:
            tbv[k] = signed[k]

        try:
            vk = VerifyingKey.from_pem(cert["public key"].encode())
        except:
            ret = False
            reason = "error in loading the public key from cert"
            return ret, reason

        js = json.dumps(tbv)
        logging.info("tbv: {}".format(js))
        logging.info("signature: {}".format(signed["signature"]))
        sig = base64.b64decode(signed["signature"].encode())

        ret = vk.verify(sig, js.encode(), hashfunc=hashlib.sha256)

    return ret, reason

def run(ifile, cfile):
    lst = []
    with open(cfile, "r") as f:
        crl = json.loads(f.read())

    with open(ifile, "r") as f:
        cert = json.loads(f.read())
    
    ret, reason = verify_signature(crl, cert)
    logging.info("ret: {}".format(ret))
    logging.info("reason: {}".format(reason))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--issuer", metavar="<issuer certificate>", help="Issuer certificate", type=str, required=True)
    parser.add_argument("-c", "--crl", metavar="<crl>", help="CRL", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.issuer, args.crl)
    
if __name__ == "__main__":
    main()
