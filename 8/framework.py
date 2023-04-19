class Framework:
    def __init__(self, crypto):
        self.crypto = crypto

    def evaluate_wall_time(self, f, params):
        pass

    def evaluate_cpu_time(self, f, params):
        pass

    def measure_memory_usage(self, f, params):
        pass

def run():
    pass

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    run()

if __name__ == "__main__":
    main()
