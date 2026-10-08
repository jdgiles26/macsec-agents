"""InventoryCollectorAgent: discover hardware, OS, software and posture.

Runs read-only system commands on macOS (sw_vers, system_profiler, sysctl,
brew, pip, csrutil, fdesetup, socketfilterfw, spctl, defaults). On other
platforms it refuses to guess and tells the user to pass --inventory-file.
"""

from __future__ import annotations

import json
import platform
import plistlib
import socket

from macsec.agents.base import Agent
from macsec.models import Inventory, SecurityPosture, SoftwareItem, utcnow
from macsec.utils import is_macos, run_command


class InventoryCollectorAgent(Agent):
    name = "inventory-collector"
    role = "recon"
    description = "Collects hardware, OS build, installed software and security posture"

    def run(self) -> Inventory:
        inv = Inventory(hostname=socket.gethostname(), collected_at=utcnow(),
                        platform=platform.system(), is_macos=is_macos())
        if not inv.is_macos:
            inv.notes.append(
                "Not running on macOS: live collection skipped. "
                "Export an inventory on the target Mac with `macsec inventory --export inv.json` "
                "and analyse it anywhere with `macsec scan --inventory-file inv.json`."
            )
            self.log("non-macOS host detected, collection skipped", "warn")
            self.ctx.inventory = inv
            return inv

        self._collect_os(inv)
        self._collect_hardware(inv)
        self._collect_software(inv)
        self._collect_posture(inv)
        self.ctx.inventory = inv
        self.log(f"{len(inv.software)} software items, macOS {inv.macos_product_version}, chip {inv.chip or 'unknown'}")
        return inv

    # -------------------------------------------------------------- OS

    def _collect_os(self, inv: Inventory) -> None:
        rc, out, _ = run_command(["sw_vers"])
        for line in out.splitlines():
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            if key == "ProductVersion":
                inv.macos_product_version = val
                try:
                    inv.macos_major = int(val.split(".")[0])
                except ValueError:
                    pass
            elif key == "BuildVersion":
                inv.macos_build = val
        inv.kernel = platform.release()
        inv.arch = platform.machine()

    # -------------------------------------------------------------- hardware

    def _collect_hardware(self, inv: Inventory) -> None:
        rc, out, _ = run_command(["system_profiler", "SPHardwareDataType", "-json"], timeout=60)
        if rc == 0 and out:
            try:
                data = json.loads(out)
                hw = data.get("SPHardwareDataType", [{}])[0]
                inv.model = hw.get("machine_name", hw.get("machine_model", ""))
                inv.chip = hw.get("chip_type", "")
            except json.JSONDecodeError:
                self.log("could not parse SPHardwareDataType", "warn")
        if not inv.chip:
            rc, out, _ = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
            if rc == 0:
                inv.chip = out

    # -------------------------------------------------------------- software

    def _collect_software(self, inv: Inventory) -> None:
        seen: set[tuple[str, str]] = set()

        def add(item: SoftwareItem) -> None:
            key = (item.name.lower(), item.version)
            if key not in seen:
                seen.add(key)
                inv.software.append(item)

        # Homebrew formulae + casks
        rc, out, _ = run_command(["brew", "list", "--versions"], timeout=120)
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if parts:
                    add(SoftwareItem(name=parts[0], version=" ".join(parts[1:]), source="brew"))
        rc, out, _ = run_command(["brew", "list", "--cask", "--versions"], timeout=120)
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if parts:
                    add(SoftwareItem(name=parts[0], version=" ".join(parts[1:]), source="brew-cask"))

        # Python packages
        for pip in ("pip3", "pip"):
            rc, out, _ = run_command([pip, "list", "--format", "json"], timeout=60)
            if rc == 0 and out.startswith("["):
                try:
                    for pkg in json.loads(out):
                        add(SoftwareItem(name=pkg["name"], version=pkg.get("version", ""), source="pip"))
                except json.JSONDecodeError:
                    pass
                break

        # GUI applications via system_profiler
        rc, out, _ = run_command(["system_profiler", "SPApplicationsDataType", "-json"], timeout=180)
        if rc == 0 and out:
            try:
                apps = json.loads(out).get("SPApplicationsDataType", [])
                for app in apps:
                    name = app.get("_name", "")
                    version = app.get("version", "")
                    if name:
                        add(SoftwareItem(name=name, version=version, source="system_profiler",
                                         raw={"path": app.get("path", "")}))
            except json.JSONDecodeError:
                self.log("could not parse SPApplicationsDataType", "warn")

        if not inv.software:
            inv.notes.append("No software inventory collected (brew/pip/system_profiler unavailable).")

    # -------------------------------------------------------------- posture

    def _collect_posture(self, inv: Inventory) -> None:
        p = SecurityPosture()

        rc, out, _ = run_command(["csrutil", "status"])
        if rc == 0:
            p.sip_enabled = "enabled" in out.lower()

        rc, out, _ = run_command(["fdesetup", "status"])
        if rc == 0:
            p.filevault_enabled = "on" in out.lower()

        rc, out, _ = run_command(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if rc == 0:
            p.firewall_enabled = "enabled" in out.lower()
        rc, out, _ = run_command(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"])
        if rc == 0:
            p.firewall_stealth = "enabled" in out.lower()

        rc, out, _ = run_command(["spctl", "--status"])
        p.gatekeeper_enabled = rc == 0 and "enabled" in out.lower()

        rc, out, _ = run_command(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                                  "AutomaticCheckEnabled"])
        if rc == 0:
            p.automatic_updates = out.strip() in ("1", "TRUE", "true")

        # XProtect version from its plist
        xp = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        try:
            with open(xp, "rb") as fh:
                info = plistlib.load(fh)
            p.xprotect_version = str(info.get("CFBundleShortVersionString", ""))
        except (OSError, ValueError):
            pass

        rc, out, _ = run_command(["systemsetup", "-getremotelogin"])
        if rc == 0:
            p.remote_login_ssh = "on" in out.lower()

        inv.posture = p
