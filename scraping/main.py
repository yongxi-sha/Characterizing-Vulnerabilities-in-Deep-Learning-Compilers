import argparse
import sys
sys.path.append('./adapters') # Add the adapters directory to the system path
from adapters.adapters import ADAPTERS

def parse_args():
    parser = argparse.ArgumentParser(description="A data scraping tool")

    parser.add_argument("--dataset", required=True, choices=ADAPTERS.keys(),
                        help="github; cve; etc")
    return parser.parse_args()


def main():
    args = parse_args()
    print(args)
    AdapterClass = ADAPTERS[args.dataset]
    adapter = AdapterClass()
    adapter.start_scraping()
    adapter.save()


if __name__ == "__main__":
    main()
