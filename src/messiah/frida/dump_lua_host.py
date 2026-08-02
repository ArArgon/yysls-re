"""
Frida host for dump_lua.js -- receives Lua chunks and writes them to disk.

Runtime dumping is the ground truth for validating static recovery: whatever
`luaU_undump` is handed is by definition a valid chunk. Compare against
statically extracted output to confirm the LuaText unpacker.

This module lives at `messiah.frida`, NOT top-level `frida`. That is
deliberate: a top-level package of that name would shadow the pip `frida`
module imported below, since editable installs put src/ on sys.path.

    python -m messiah.frida.dump_lua_host -f <exe>
    python -m messiah.frida.dump_lua_host -n <process-name>
    python -m messiah.frida.dump_lua_host <pid>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import frida  # the pip package, not this module's directory

SCRIPT_PATH = Path(__file__).parent / "dump_lua.js"


def make_handler(out_dir: Path):
    def on_message(message, data):
        if message["type"] == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "lua_dump":
                destination = out_dir / Path(payload["path"]).name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                print(
                    f"[host] #{payload['index']} {payload['size']} bytes "
                    f"-> {destination}  ({payload['name']})"
                )
        elif message["type"] == "error":
            print(f"[frida] {message['description']}", file=sys.stderr)
            if "stack" in message:
                print(message["stack"], file=sys.stderr)

    return on_message


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("pid", nargs="?", type=int, help="PID of a running process.")
    target.add_argument("-f", "--spawn", metavar="EXE", help="Spawn and attach.")
    target.add_argument("-n", "--name", metavar="NAME", help="Attach by process name.")
    parser.add_argument("--out-dir", type=Path, default=Path("lua_dump"))
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    device = frida.get_local_device()
    js = SCRIPT_PATH.read_text(encoding="utf-8")

    pid_to_resume = None
    if args.spawn:
        print(f"[host] spawning {args.spawn}")
        pid_to_resume = device.spawn([args.spawn])
        session = device.attach(pid_to_resume)
    else:
        handle = args.name if args.name else args.pid
        print(f"[host] attaching to {handle}")
        session = device.attach(handle)

    script = session.create_script(js)
    script.on("message", make_handler(args.out_dir))
    script.load()

    if pid_to_resume is not None:
        device.resume(pid_to_resume)

    print(f"[host] dumping to {args.out_dir.resolve()}")
    print("[host] Ctrl+C to detach.\n")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[host] detaching")
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
