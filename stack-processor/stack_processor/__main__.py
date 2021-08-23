import argparse
from .processor import StackProcessor

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Stack processor powered by Team Crypt0newbies"
    )
    parser.add_argument("filepath", type=str, help="a stack program file to run")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    data = []
    with open(args.filepath) as f:
        for line in f:
            data.append(line.strip())
    processor = StackProcessor(data, verbose=args.verbose)
    print(processor.run())
