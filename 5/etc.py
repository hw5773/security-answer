def generate_messages():
    ret = {}
    ret[0] = "hello"
    ret[1] = "world"
    ret[2] = "security"
    ret[3] = "computer"
    ret[4] = "kentech"
    ret[5] = "energy"
    ret[6] = "artificial"
    ret[7] = "intelligence"
    ret[8] = "network"
    ret[9] = "cryptography"
    return ret

def generate_c2i_mapper():
    ret = {}
    for i in range(ord('a'), ord('z')+1):
        ret[chr(i)] = i - ord('a')
    return ret

def generate_i2c_mapper():
    ret = {}
    for i in range(26):
        ret[i] = chr(i+97)
    return ret
