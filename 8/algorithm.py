import logging

class Algorithm:
    def __init__(self, name):
        self.name = name
        self.params = {}
        self.asymmetric = None
        self.keypair = {}

    def get_name(self):
        return self.name

    def get_parameters(self):
        return self.params

    def is_asymmetric(self):
        return self.asymmetric
    
    def get_keypair(self):
        return self.keypair

    def key_generation(self):
        pass

    def encryption(self, message):
        pass

    def decryption(self, ciphertext):
        pass

    def print_keypair(self):
        pass
