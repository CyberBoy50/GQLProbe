#!/usr/bin/env python3
"""GQLProbe launcher — setup, probe, test, doctor, lab, menu.

Usage:
    python run.py setup            # create venv + requests (first time)
    python run.py probe <url> ...  # probe an endpoint (flags pass through)
    python run.py test             # run the 8 build-plan step tests
    python run.py doctor           # check the setup
    python run.py lab [config]     # start the lab API (vulnerable default)
    python run.py menu             # open the numbered menu

Cross-platform: pure Python, Windows/macOS/Linux. Plain
`python3 gqlprobe.py` also works (requests preferred, urllib fallback).
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def venv_python():
    """Path of the venv Python for this OS, or None if no venv yet."""
    if os.name == "nt":
        cand = os.path.join(HERE, "venv", "Scripts", "python.exe")
    else:
        cand = os.path.join(HERE, "venv", "bin", "python")
    return cand if os.path.isfile(cand) else None


def run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def ensure_venv():
    """Create the venv if needed. Returns the Python to use."""
    vp = venv_python()
    if vp is None:
        print("[*] Creating virtual environment (first time only)...")
        rc = run([sys.executable, "-m", "venv",
                  os.path.join(HERE, "venv")]).returncode
        if rc != 0:
            print("[!] Could not create a venv. Using system Python.")
            return sys.executable
        vp = venv_python()
    return vp


def cmd_setup(_args):
    vp = ensure_venv()
    print("[*] Installing requests (optional — the probe falls back "
          "to urllib without it)...")
    rc = run([vp, "-m", "pip", "install", "-q", "requests"]).returncode
    if rc != 0:
        print("[!] pip install failed — the probe still works: it "
              "falls back to urllib (stdlib).")
    print("[+] Setup done. Python: %s" % vp)
    print("    Test it: python run.py lab vulnerable")
    print("             python run.py probe http://127.0.0.1:4000/graphql "
          "--token lab-token-alice")
    return 0


def cmd_probe(args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "gqlprobe.py")] + args).returncode


def cmd_test(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "test_gqlprobe.py")]).returncode


def cmd_doctor(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "gqlprobe.py"),
                "--check"]).returncode


def cmd_lab(args):
    vp = venv_python() or sys.executable
    config = args[0] if args else "vulnerable"
    rest = args[1:] if len(args) > 1 else []
    return run([vp, os.path.join(HERE, "lab_api.py"),
                "--config", config] + rest).returncode


def cmd_menu(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "gqlprobe.py"),
                "--menu"]).returncode


def usage():
    print(__doc__.strip())
    return 2


COMMANDS = {
    "setup": cmd_setup,
    "probe": cmd_probe,
    "test": cmd_test,
    "doctor": cmd_doctor,
    "lab": cmd_lab,
    "menu": cmd_menu,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return usage()
    cmd = argv[0]
    if cmd not in COMMANDS:
        print("[!] Unknown command: %s" % cmd)
        return usage()
    return COMMANDS[cmd](argv[1:])


if __name__ == "__main__":
    sys.exit(main())
