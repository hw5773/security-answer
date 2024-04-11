import requests
import argparse
import logging
import os
import sys
import hashlib

def parse_problem(pname):
    ret = {}
    num = 0

    with open(pname, "r") as f:
        for line in f:
            ret[num] = {}
            k, v = line.strip().split(": ")
            if k == "url":
                ret[num]["url"] = v.strip()
            else:
                logging.error("parse error. it is not a URL")
                ret = None
                break
            
            line = f.readline()
            k, v = line.strip().split(": ")
            if k == "hash":
                ret[num]["answer"] = v.strip()
            else:
                logging.error("parse error. it is not a hash value")
                ret = None
                break
            num += 1
        
    return ret

def digest(content):
    m = hashlib.sha256()
    m.update(content)
    return m.hexdigest()

def run(problem):
    problems = parse_problem(problem)
    if not problems:
        logging.error("error happens. try again.")
    else:
        for k in problems:
            content = requests.get(problems[k]["url"]).content
            h = digest(content)
            a = problems[k]["answer"]
            logging.info("===== problem: {} =====".format(k))
            logging.info("Result: {}".format(h == a))
            logging.info("  - Hash: {}".format(h))
            logging.info("  - Answer: {}".format(a))
            print ("\n")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--problem", metavar="<File name that contains the url of a file and the hash value of it>", help="File name that contains the URL of a file and the hash value of it", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    if not os.path.exists(args.problem):
        logging.error("File ({}) not exists".format(args.hash))
        sys.exit(1)

    run(args.problem)

if __name__ == "__main__":
    main()
