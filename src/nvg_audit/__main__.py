import argparse
import json
import os
import sys

from nvg_key_material.files import Unavailable

from .config import load_config
from .engine import discover, execute, exit_code
from .privacy import redact


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments; consult --help.\n")


def main(argv=None):
    parser = Parser(description="nOS security regression cases in disposable local namespaces")
    parser.add_argument("--list-plugins", action="store_true")
    parser.add_argument("--target-config")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--plugin", action="append")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--format", choices=["json"], default="json")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.list_plugins:
            modules, errors = discover()
            print(json.dumps(redact({"plugins": sorted(modules), "unavailable": errors}), indent=2))
            return 3 if errors else 0
        config = load_config(args.target_config)
        report = execute(config, args.plugin)
        raw = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(raw)
        else:
            sys.stdout.write(raw)
        return exit_code(report)
    except (Unavailable, OSError, ValueError, TypeError):
        print("Configuration, selection, or output unavailable; no input content is logged.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
