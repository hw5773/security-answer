import socket
import threading
import argparse
import logging
import random
import base64
import os
import sys
import json

def load_certificates(cdir, odir):
    subjects = ['.'.join(f.split(".")[0:-1]) for f in os.listdir(cdir) if "www" in f]
    certs = {}

    for subject in subjects:
        certs[subject] = {}
        certs[subject]["chain"] = []
        with open("{}/{}.crt".format(cdir, subject), "r") as f:
            cert = json.loads(f.read())
            issuer = cert["issuer"]
            certs[subject]["chain"].append(json.dumps(cert))

            with open("{}/{}.crt".format(cdir, issuer), "r") as ff:
                icert = json.loads(ff.read())
                certs[subject]["chain"].append(json.dumps(icert))

        if os.path.exists("{}/{}.ocsp".format(odir, subject)):
            with open("{}/{}.ocsp".format(odir, subject)) as f:
                certs[subject]["ocsp"] = f.read()
        else:
            certs[subject]["ocsp"] = "none"
    
    return certs

def handler(alice, certs):
    finished = False

    while not finished:
        received = alice.recv(1024).decode()
        logging.info("[*] URL (received): {}".format(received))
        
        if received == "finished":
            finished = True
        elif received == "www.gary.com":
            reply = certs["www.geno.com"]
            alice.send(json.dumps(reply).encode())
        else:
            reply = certs[received]
            alice.send(json.dumps(reply).encode())

    alice.close()

def run(addr, port, cdir, odir):
    certs = load_certificates(cdir, odir)

    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, certs))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-c", "--cdir", metavar="<directory that contains certificates>", help="Directory that contains certificates", type=str, required=True)
    parser.add_argument("-o", "--odir", metavar="<directory that contains ocsp staples>", help="Directory that contains ocsp staples", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if not os.path.exists(args.cdir):
        logging.error("The directory specified for certificates does not exist: {}".format(args.cdir))
        sys.exit(1)

    if not os.path.exists(args.odir):
        logging.error("The directory specified for ocsp staples does not exist: {}".format(args.odir))
        sys.exit(1)


    run(args.addr, args.port, args.cdir, args.odir)

if __name__ == "__main__":
    main()
