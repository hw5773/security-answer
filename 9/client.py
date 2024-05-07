import socket
import argparse
import logging
import random
from func import encrypt, decrypt

BUF_SIZE = 1024

def generate_shared_key(p, g, my_priv, my_pub, other_pub):
    pass

def generate_dh_keypair(p, g):
    pass

def is_generator(p, g):
    pass

def select_generator(p):
    g = random.randint(1, p-1)
    while not is_generator(p, g):
        g = random.randint(1, p-1)
    return g

def run(addr, port, message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))

    p = 19
    g = select_generator(p)

    logging.info("[*] Prime number selected: {}".format(p))
    logging.info("[*] Generator selected: {}".format(g))

    my_priv, my_pub = generate_dh_keypair(p, g)
    logging.info("[*] My DH private key: {}".format(my_priv))
    logging.info("[*] My DH public key: {}".format(my_pub))

    params = "{}:{}:{}".format(p, g, my_pub)
    client.send(params.encode())

    materials = client.recv(BUF_SIZE)
    materials = materials.decode()
    other_pub = int(materials)
    logging.info("[*] Other's DH public key: {}".format(other_pub))

    k = generate_shared_key(p, g, my_priv, my_pub, other_pub)
    logging.info("[*] Established shared key: {}".format(k))

    plaintext = message
    ciphertext = encrypt(k, plaintext)
    logging.info("[*] Plaintext (to Server, to be encrypted): {}".format(message))
    logging.info("[*] Ciphertext (to Server, encrypted): {}".format(ciphertext))
    client.send(ciphertext.encode())

    ciphertext = client.recv(BUF_SIZE)
    ciphertext = ciphertext.decode()
    logging.info("[*] Ciphertext (from Server, to be decrypted): {}".format(ciphertext))
    plaintext = decrypt(k, ciphertext)
    logging.info("[*] Plaintext (from Server, decrypted): {}".format(plaintext))

    if message == plaintext:
        logging.info("[*] Correct!")
        client.send("correct".encode())
    else:
        logging.info("[*] Incorrect!")
        client.send("incorrect".encode())

    logging.info("[*] Finished!")
    client.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<server's address>", help="Server's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<server's port>", help="Server's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message to be sent", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.message)
    
if __name__ == "__main__":
    main()
