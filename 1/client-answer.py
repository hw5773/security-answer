import socket
import argparse
import logging

def run(addr, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((addr, port))
    logging.info("Client is connected to {}:{}".format(addr, port))
    client.send("Hello".encode())
    response = client.recv(10)
    logging.info("Response: {}".format(response.decode()))
    response = client.recv(1024)
    logging.info("Response: {}".format(response.decode()))
    client.send("I am Sam".encode())

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<server's address>", help="Server's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<server's port>", help="Server's port", type=int, required=True)
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
