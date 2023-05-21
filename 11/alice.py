from ecdsa import VerifyingKey, NIST256p
import socket
import argparse
import logging
import base64
import os
import sys
import json

# verify the signature in "signed" (JSON object) based on the public key in "cert" (JSON object)
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
        logging.debug("before: {}".format(keys))
        keys.remove("signature")
        logging.debug("after: {}".format(keys))

        for k in keys:
            tbv[k] = signed[k]

        try:
            vk = VerifyingKey.from_pem(cert["public key"].encode())
        except:
            ret = False
            reason = "error in loading the public key from cert"
            return ret, reason

        js = json.dumps(tbv)
        sig = base64.b64decode(signed["signature"].encode())

        try:
            ret = vk.verify(sig, js.encode(), hashfunc=hashlib.sha256)
        except:
            ret = False
            reason = "verification failure"

    return ret, reason

def chain_validation(chain, trusted):
    curr = chain[0]
    for issuer in chain[1:]:
        ret, reason = verify_signature(curr, issuer)
        if ret:
            curr = issuer
        else:
            break
    
    if curr["subject"] == curr["issuer"]:
        if curr["subject"] in trusted:
            ret = True
            reason = "success"
        else:
            ret = False
            reason = "not trusted"
    else:
        if curr["issuer"] in trusted:
            ret, reason = verify_signature(curr, trusted[curr["issuer"]])
            if ret:
                ret = True
                reason = "success"
            else:
                ret = False
                reason = "not trusted"
        else:
            ret = False
            reason = "not trusted"

    return ret, reason

def name_validation(url, chain):
    leaf = chain[0]
    if url == leaf["subject"]:
        ret = True
        reason = "success"
    else:
        ret = False
        reason = "invalid subject name"
    return ret, reason

def revocation_checking(chain, crl, ocsp):
    curr = int(time.time())

    # 1. validity checking
    for cert in chain:
        if curr < cert["not before"]:
            ret = False
            reason = "invalid certificate (not before) at {}".format(cert["subject"])
            break
        elif curr > cert["not after"]:
            ret = False
            reason = "invalid certificate (not after) at {}".format(cert["subject"])
            break
        else:
            ret = True
            reason = "success"

    if not ret:
        return ret, reason
    
    # 2. revocation checking (crl or ocsp)

    return False, "not implemented"

def validate_certificate(url, chain, trusted, crl, ocsp):
    ret = False

    chain_verified, reason = chain_validation(chain, trusted)
    if chain_verified:
        name_verified, reason = name_validation(url, chain)

        if name_verified: 
            revocation_verified, reason = revocation_checking(chain, crl, ocsp)

            if revocation_verified:
                ret = True

    return ret, reason

def load_crls(cdir):
    crl = {}
    clst = [f.split(".")[0] for f in os.listdir(cdir)]

    for ca in clst:
        with open("{}/{}.crl".format(cdir, ca), "r") as f:
            crl[ca] = json.loads(f.read())

    return crl

def load_trusted_root_ca(tdir):
    trusted = {}
    tlst = [f.split(".")[0] for f in os.listdir(tdir)]

    for ca in tlst:
        with open("{}/{}.crt".format(tdir, ca), "r") as f:
            trusted[ca] = json.loads(f.read())

    return trusted

def run(addr, port, rfile, cdir, tdir):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))

    # crl: ca name -> crl
    crl = load_crls(cdir)

    # trusted: ca name -> ca's certificate
    trusted = load_trusted_root_ca(tdir)

    with open(rfile, "r") as f:
        for line in f:
            if line.strip() == '':
                break
            url = line.strip()
            alice.send(url.encode())
            logging.info("[*] Sent: {}".format(url))
            received = alice.recv(2048).decode()
            logging.debug("[*] Received: {}".format(received))
            js = json.loads(received)
            chain = js["chain"]
            ocsp = js["ocsp"]
            verified, reason = validate_certificate(url, chain, trusted, crl, ocsp)
            logging.info("[*] Result of Certificate Validation ({}): {} ({})".format(url, verified, reason))

    alice.send("finished".encode())

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-r", "--request", metavar="<request file>", help="Request file name", type=str, required=True)
    parser.add_argument("-c", "--crl", metavar="<crl directory>", help="CRL directory", type=str, required=True)
    parser.add_argument("-t", "--trusted", metavar="<trusted ca directory>", help="Trusted CA directory", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if not os.path.exists(args.request):
        logging.error("The request file does not exist: {}".format(args.request))
        sys.exit(1)

    if not os.path.exists(args.crl):
        logging.error("The directory specified for CRL does not exist: {}".format(args.crl))
        sys.exit(1)

    if not os.path.exists(args.trusted):
        logging.error("The directory specified for trusted root CA does not exist: {}".format(args.trusted))
        sys.exit(1)

    run(args.addr, args.port, args.request, args.crl, args.trusted)
    
if __name__ == "__main__":
    main()
