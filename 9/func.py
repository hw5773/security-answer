import base64
import logging

def encrypt(k, plaintext):
    try:
        tmp = []
        for p in plaintext:
            tmp.append(k^ord(p))
            logging.debug("k: {}, p: {}, k^p: {}".format(k, p, k^ord(p)))
        ciphertext = base64.b64encode(bytes(tmp)).decode()
        logging.debug("ciphertext: {}".format(ciphertext))
        return ciphertext
    except:
        return "error"

def decrypt(k, ciphertext):
    try:
        ciphertext = ciphertext.encode()
        ciphertext = base64.b64decode(ciphertext)
        logging.debug("ciphertext: {}".format(ciphertext))
        plaintext = ""
        for c in ciphertext:
            plaintext += chr(k^c)
            logging.debug("k: {}, c: {}, k^c: {}".format(k, c, chr(k^c)))
    
        logging.debug("plaintext: {}".format(plaintext))
        return plaintext
    except:
        return "error"
