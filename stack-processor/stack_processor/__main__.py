import sys
from .processor import StackProcessor

if __name__ == "__main__":
    data = []
    with open(sys.argv[1]) as f:
        for lines in f:
            for word in lines.split():
                data.append(word)
    processor = StackProcessor(data)
    print(processor.run())
