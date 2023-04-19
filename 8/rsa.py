import logging
import base64
from algorithm import Algorithm
from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_OAEP

class RSA(Algorithm):
    def __init__(self, name, klen):
        super().__init__(name)
        self.params["klen"] = klen
        self.asymmetric = True

    def key_generation(self):
        key = rsa.generate(self.params["klen"])
        private_key = key
        public_key = key.publickey()

        self.keypair["private"] = private_key
        self.keypair["public"] = public_key

    def encryption(self, message):
        oaep = PKCS1_OAEP.new(self.keypair["public"])
        encrypted = base64.b64encode(oaep.encrypt(message.encode())).decode()
        logging.debug("encrypted ({} bytes): {}".format(len(encrypted), encrypted))
        return encrypted

    def decryption(self, ciphertext):
        oaep = PKCS1_OAEP.new(self.keypair["private"])
        decrypted = oaep.decrypt(base64.b64decode(ciphertext)).decode()
        logging.debug("decrypted ({} bytes): {}".format(len(decrypted), decrypted))
        return decrypted

    def print_keypair(self):
        private = self.keypair["private"].export_key("DER")
        public = self.keypair["public"].export_key("DER")
        logging.info("Print {}'s keypair ===".format(self.get_name()))
        logging.info("  - private key ({} bytes): {}".format(len(private), private))
        logging.info("  - public key ({} bytes): {}".format(len(public), public))
