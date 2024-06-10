from ecdsa import SigningKey, NIST256p
import argparse
import logging
import sys
import json
import base64
import random
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

def run(subject, issuer, not_before, not_after):
    sk = SigningKey.generate()
    vk = sk.verifying_key

    with open("{}.key".format(subject), "wb") as f:
        f.write(sk.to_pem())

    cert = {}
    cert["subject"] = subject
    cert["issuer"] = issuer
    cert["serial"] = random.randrange(100000000)
    cert["not before"] = not_before
    cert["not after"] = not_after
    cert["public key"] = vk.to_pem().decode()

    signature = sign(issuer, cert)

    cert["signature"] = signature

    with open("{}.crt".format(subject), "w") as f:
        js = json.dumps(cert)
        f.write(js)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--subject", metavar="<subject name>", help="Subject name", type=str, required=True)
    parser.add_argument("-i", "--issuer", metavar="<issuer name>", help="Issuer name", type=str, required=True)
    parser.add_argument("-a", "--not-after", metavar="<not after>", help="Not after", type=str, required=True)
    parser.add_argument("-b", "--not-before", metavar="<not before>", help="Not before", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    random.seed()

    run(args.subject, args.issuer, args.not_before, args.not_after)
    
if __name__ == "__main__":
    main()
