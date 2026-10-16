"""
Per-session data-channel controls for RDP (clipboard, file transfer, printing).

Default deny. The parameter names are the ones guacd 1.6.0 announces for the `rdp` protocol (checked against
the running guacd's `args` list, not assumed): disable-copy, disable-paste, enable-drive, disable-download,
disable-upload, enable-printing, enable-sftp. guacd silently ignores a name it does not know, so a misspelt
setting would look secure and do nothing - hence the explicit values and the test that pins the names.

Clipboard is enabled only when the asset has an attached policy that explicitly allows it. File transfer is
never enabled: Guacamole file transfer needs a drive store on guacd's filesystem that SecurePAM does not
isolate, retain or audit, and the gateway sees no per-file events. A policy's download/upload flags therefore
do NOT turn it on; a switch we cannot enforce and audit would be cosmetic.

The gateway also enforces the clipboard decision itself on the browser->guacd direction and counts what passes
the relay. It records only that clipboard instructions happened - never their contents.
"""
import re
from dataclasses import dataclass
from typing import Dict, Optional, Set


@dataclass(frozen=True)
class RdpControls:
    clipboard: bool = False
    file_transfer: bool = False  # always False: see module docstring


def resolve_controls(policy) -> RdpControls:
    """Default deny. `policy` is the asset's attached Policy row, or None."""
    allowed = policy is not None and getattr(policy, "clipboard_allowed", False) is True
    return RdpControls(clipboard=allowed, file_transfer=False)


def channel_params(controls: RdpControls) -> Dict[str, str]:
    blocked = "false" if controls.clipboard else "true"
    return {
        "disable-copy": blocked,           # remote -> browser clipboard
        "disable-paste": blocked,          # browser -> remote clipboard
        "enable-drive": "false",           # no drive redirection / file transfer
        "disable-download": "true",
        "disable-upload": "true",
        "enable-printing": "false",
        "enable-sftp": "false",
    }


_CLIENT_NAME_MAX = 15  # the RDP client name is a NetBIOS-style name; Windows truncates beyond 15 characters


def client_name(session_number: Optional[str]) -> str:
    """The SecurePAM session number as the RDP client name (guacd parameter `client-name`).

    It is sent to Windows during the RDP/NLA handshake and may appear as the workstation/client name in Windows
    logon and session events (e.g. 4624, 4778) - verify that on the target; it is not assumed. Only [A-Z0-9-]
    survive, so nothing from a request can inject odd characters into the handshake.
    """
    cleaned = re.sub(r"[^A-Za-z0-9-]", "", session_number or "").upper()[:_CLIENT_NAME_MAX]
    return cleaned or "SECUREPAM"


def audit_summary(controls: RdpControls) -> Dict[str, bool]:
    return {"clipboard": controls.clipboard, "file_transfer": controls.file_transfer}


class ClipboardGate:
    """Counts clipboard instructions crossing the relay and drops browser->guacd ones when not permitted.

    Guacamole clipboard transfer is a stream: `clipboard,<stream>,<mimetype>` then `blob,<stream>,<data>`... then
    `end,<stream>`. When the opening instruction is dropped, the matching blob/end are dropped too. Contents are
    never stored or logged; only counts are kept.
    """

    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed
        self.from_browser = 0   # clipboard transfers the browser attempted
        self.blocked = 0        # of those, dropped at the gateway
        self.from_remote = 0    # clipboard transfers guacd sent toward the browser
        self._dropped: Set[str] = set()

    def client_instruction(self, ins) -> bool:
        """True if this browser instruction may be forwarded to guacd."""
        if not ins:
            return False
        op = ins[0]
        if op == "clipboard":
            self.from_browser += 1
            if self.allowed:
                return True
            self.blocked += 1
            if len(ins) > 1:
                self._dropped.add(ins[1])
            return False
        if op in ("blob", "end") and len(ins) > 1 and ins[1] in self._dropped:
            if op == "end":
                self._dropped.discard(ins[1])
            return False
        return True

    def server_instruction(self, ins) -> None:
        if ins and ins[0] == "clipboard":
            self.from_remote += 1

    @property
    def active(self) -> bool:
        return bool(self.from_browser or self.from_remote)

    def summary(self) -> Optional[Dict[str, object]]:
        if not self.active:
            return None
        return {"clipboard_policy": "allowed" if self.allowed else "blocked",
                "browser_to_remote_transfers": self.from_browser, "blocked_at_gateway": self.blocked,
                "remote_to_browser_transfers": self.from_remote, "content_captured": False}
