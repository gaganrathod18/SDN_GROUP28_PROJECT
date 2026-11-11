"""Shared helpers for the automated tests: run commands, start/stop POX, run PacMan on a pty."""
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time

sys.dont_write_bytecode = True
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(PROJECT, "results")
PACMAN = os.environ.get("PACMAN_BIN", os.path.join(os.path.dirname(PROJECT), "pacman", "build", "pacman"))
sys.path.insert(0, os.path.join(PROJECT, "topology"))


class Report(object):
    """Collects PASS/FAIL lines and writes them to results/<name>."""

    def __init__(self, title):
        self.lines, self.results = [], []
        self.say("%s  ·  %s" % (title, time.strftime("%Y-%m-%d %H:%M:%S")))
        self.say("=" * 60)

    def say(self, text=""):
        print(text, flush=True)
        self.lines.append(text)

    def check(self, cid, name, ok, detail=""):
        self.results.append((cid, bool(ok)))
        self.say("[%s] %-4s %s%s" % ("PASS" if ok else "FAIL", cid, name, ("  -> " + detail) if detail else ""))
        return ok

    def finish(self, filename):
        passed = sum(1 for _, ok in self.results if ok)
        self.say("=" * 60)
        self.say("%d/%d checks passed" % (passed, len(self.results)))
        path = os.path.join(RESULTS, filename)
        with open(path, "w") as f:
            f.write("\n".join(self.lines) + "\n")
        return passed == len(self.results)


def sh(cmd, timeout=60):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def require_sudo(script):
    if os.geteuid() != 0 or not os.environ.get("SUDO_USER"):
        sys.exit("run with sudo from your normal user:  sudo python3 scripts/%s" % script)
    if not os.access(PACMAN, os.X_OK):
        sys.exit("PacMan binary not found: %s" % PACMAN)


def as_user(cmd, timeout=60):
    """Run a command as the invoking user (rootless Podman lives there, not under root)."""
    uid = int(os.environ.get("SUDO_UID", "0"))
    return sh("runuser -u %s -- env XDG_RUNTIME_DIR=/run/user/%d %s" % (os.environ["SUDO_USER"], uid, cmd), timeout)


def pox_start(**env):
    pairs = " ".join("%s=%s" % kv for kv in env.items())
    return as_user("env %s %s/scripts/run_pox.sh -d" % (pairs, PROJECT))


def pox_stop():
    as_user("podman rm -f -t 0 pacman-pox")


def pox_logs():
    return as_user("podman logs pacman-pox")[1]


def wait_for(fn, timeout, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(step)
    return False


def no_loss(ping_output):
    return re.search(r"(?<!\d)0% packet loss", ping_output) is not None


def full_loss(ping_output):
    return "100% packet loss" in ping_output


def all_connected(n=3):
    _, out = sh("ovs-vsctl --columns=is_connected list controller")
    vals = re.findall(r"is_connected\s*:\s*(\w+)", out)
    return len(vals) == n and all(v == "true" for v in vals)


def drop_rule(switch, ip):
    """The controller's drop rule for `ip` on `switch`, or '' if absent."""
    _, out = sh("ovs-ofctl dump-flows %s 'ip,nw_src=%s'" % (switch, ip))
    return next((l.strip() for l in out.splitlines() if "actions=drop" in l), "")


def remove(*names):
    for name in names:
        try:
            os.remove(os.path.join(RESULTS, name))
        except FileNotFoundError:
            pass


def read(name):
    try:
        with open(os.path.join(RESULTS, name)) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def give_results_to_user():
    sh("chown -R %s:%s %s" % (os.environ["SUDO_UID"], os.environ["SUDO_GID"], RESULTS))


class PacManLive(object):
    """PacMan's live dashboard on a pseudo-terminal, kept running in the background."""

    def __init__(self, config="config/pacman-sdn.conf", iface="mon0"):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 170, 0, 0))
        self.proc = subprocess.Popen("cd %s && exec %s live %s --iface %s" % (PROJECT, PACMAN, config, iface),
                                     shell=True, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        self.master = master
        threading.Thread(target=self._drain, daemon=True).start()   # the dashboard writes constantly

    def _drain(self):
        while True:
            try:
                if select.select([self.master], [], [], 0.5)[0] and not os.read(self.master, 65536):
                    break
            except OSError:
                break

    def running(self):
        return self.proc.poll() is None

    def stop(self):
        if self.running():
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
        try:
            os.close(self.master)
        except OSError:
            pass
