import argparse
import logging

def euclid(a, b):
    if a < b:
        return euclid(b, a)

    if b == 0:
        return a
    else:
        return euclid(b, a % b)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", metavar="<number a>", help="Number a", type=int, required=True)
    parser.add_argument("-b", metavar="<number b>", help="Number b", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    a = args.a
    b = args.b
    gcd = euclid(a, b)
    logging.info("Number a: {}, Number b: {}, gcd: {}".format(a, b, gcd))
    
if __name__ == "__main__":
    main()
