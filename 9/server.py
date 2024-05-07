import sys
import random
import socket
import threading
import argparse
import logging
from func import encrypt, decrypt

BUF_SIZE = 1024

def generate_shared_key(p, g, my_priv, my_pub, other_pub):
    pass

def generate_dh_keypair(p, g):
    pass

def is_generator(p, g):
    pass

def handler(client):
    params = client.recv(BUF_SIZE)
    params = params.decode().strip()
    logging.info("[*] Received: {}".format(params))
    try:
        p, g, other_pub = params.split(":")
        p = int(p)
        g = int(g)
        other_pub = int(other_pub)
    except ValueError:
        logging.error("[*] Maybe Client is not fully implemented?")
        client.close()
        sys.exit(1)

    if not is_generator(p, g):
        logging.error("The generator selected by a client is not actually a generator.")
        client.send("error".encode())

    logging.info("[*] Prime number selected: {}".format(p))
    logging.info("[*] Generator selected: {}".format(g))

    my_priv, my_pub = generate_dh_keypair(p, g)
    logging.info("[*] My DH private key: {}".format(my_priv))
    logging.info("[*] My DH public key: {}".format(my_pub))
    logging.info("[*] Other's DH public key: {}".format(other_pub))

    k = generate_shared_key(p, g, my_priv, my_pub, other_pub)
    logging.info("[*] Established shared key: {}".format(k))

    materials = "{}".format(my_pub)
    client.send(materials.encode())

    ciphertext = client.recv(BUF_SIZE)
    ciphertext = ciphertext.decode()
    if len(ciphertext) == 0:
        logging.error("[*] Maybe Client is not fully implemented?")
        client.close()
        sys.exit(1)
    
    plaintext = decrypt(k, ciphertext)
    logging.info("[*] Ciphertext (from Client, to be decrypted): {}".format(ciphertext))
    logging.info("[*] Plaintext (from Client, decrypted): {}".format(plaintext))

    ciphertext = encrypt(k, plaintext)
    logging.info("[*] Plaintext (to Client, to be encrypted): {}".format(plaintext))
    logging.info("[*] Ciphertext (to Client, encrypted): {}".format(ciphertext))
    client.send(ciphertext.encode())

    result = client.recv(BUF_SIZE)
    result = result.decode()

    if result == "correct":
        logging.info("[*] Correct!")
    else:
        logging.info("[*] Incorrect!")

    client.close()
    logging.info("[*] Finished!")

def run(addr, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr, port))

    server.listen(2)
    logging.info("[*] Server is listening on {}:{}".format(addr, port))

    while True:
        client, info = server.accept()

        logging.info("[*] Server accepts the connection from {}:{}".format(info[0], info[1]))

        client_handle = threading.Thread(target=handler, args=(client,))
        client_handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<server's IP address>", help="Server's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<server's open port>", help="Server's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()
