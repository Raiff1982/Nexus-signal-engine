# hoax_scan.py
import argparse
import sys
import json
from nexis_signal_engine import NexisSignalEngine

def json_dump(obj):
    """Helper to pretty-print JSON."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

def main():
    p = argparse.ArgumentParser(description="Nexis/Nexus hoax scan")
    p.add_argument("--db", default="signals.db", help="SQLite DB path (.db)")
    p.add_argument("--source", default=None, help="Source URL (optional)")
    p.add_argument("text", nargs="*", help="Text to scan (or stdin)")
    args = p.parse_args()

    engine = NexisSignalEngine(memory_path=args.db)

    if args.text:
        text = " ".join(args.text)
    else:
        text = sys.stdin.read()

    result = engine.process_news(text, source_url=args.source)
    print(json_dump(result))

if __name__ == "__main__":
    main()