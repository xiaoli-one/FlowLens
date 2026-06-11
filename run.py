import argparse
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Start passive scanner proxy.")
    parser.add_argument("--host", default="127.0.0.1", help="Proxy listen host")
    parser.add_argument("--port", default="8081", help="Proxy listen port")
    parser.add_argument(
        "--log-file",
        default=os.path.join("logs", "flows.jsonl"),
        help="Where captured traffic will be written",
    )
    args = parser.parse_args()

    addon_path = os.path.join(os.path.dirname(__file__), "pass_scan", "mitm_addon.py")
    log_dir = os.path.dirname(args.log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    env = os.environ.copy()
    env["PASS_SCAN_LOG_FILE"] = args.log_file

    command = [
        "mitmdump",
        "--listen-host",
        args.host,
        "--listen-port",
        str(args.port),
        "--mode",
        "regular",
        "-s",
        addon_path,
    ]

    print(f"[*] Passive scanner proxy listening on {args.host}:{args.port}")
    print(f"[*] Traffic log: {args.log_file}")
    print("[*] Press Ctrl+C to stop")

    try:
        subprocess.run(command, env=env, check=False)
    except FileNotFoundError:
        print("\n[!] mitmdump not found. Install dependencies first:")
        print("    python3 -m pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
