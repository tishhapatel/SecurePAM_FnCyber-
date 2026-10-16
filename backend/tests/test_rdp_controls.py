"""RDP data-channel controls: default deny, explicit policy only, no content ever captured."""
from types import SimpleNamespace

from app.services.guacamole import encode
from app.services.rdp_controls import ClipboardGate, audit_summary, channel_params, client_name, resolve_controls


def test_default_is_deny_everything():
    for policy in (None, SimpleNamespace(clipboard_allowed=False), SimpleNamespace()):
        c = resolve_controls(policy)
        assert (c.clipboard, c.file_transfer) == (False, False)
        p = channel_params(c)
        assert (p["disable-copy"], p["disable-paste"]) == ("true", "true")
        assert (p["enable-drive"], p["disable-download"], p["disable-upload"]) == ("false", "true", "true")
        assert (p["enable-printing"], p["enable-sftp"]) == ("false", "false")


def test_only_an_explicit_policy_allows_clipboard_and_never_file_transfer():
    # download_allowed/upload_allowed are True by default on Policy; they must NOT enable file transfer.
    policy = SimpleNamespace(clipboard_allowed=True, download_allowed=True, upload_allowed=True)
    c = resolve_controls(policy)
    assert c.clipboard is True and c.file_transfer is False
    p = channel_params(c)
    assert (p["disable-copy"], p["disable-paste"]) == ("false", "false")
    assert (p["enable-drive"], p["disable-download"], p["disable-upload"]) == ("false", "true", "true")
    assert audit_summary(c) == {"clipboard": True, "file_transfer": False}
    assert resolve_controls(SimpleNamespace(clipboard_allowed="yes")).clipboard is False  # strictly True only


def test_parameter_names_are_the_ones_guacd_announces():
    # guacd 1.6.0 `args` for rdp (verified against the running guacd); unknown names are silently ignored.
    announced = {"disable-copy", "disable-paste", "enable-drive", "disable-download", "disable-upload",
                 "enable-printing", "enable-sftp"}
    assert set(channel_params(resolve_controls(None))) == announced


def test_blocked_gate_drops_the_whole_clipboard_stream_and_counts_without_content():
    gate = ClipboardGate(allowed=False)
    secret = "c2VjcmV0LXBhc3RlZC10ZXh0"
    assert gate.client_instruction(("clipboard", "3", "text/plain")) is False
    assert gate.client_instruction(("blob", "3", secret)) is False
    assert gate.client_instruction(("blob", "9", "bW91c2U=")) is True      # another stream is untouched
    assert gate.client_instruction(("end", "3")) is False
    assert gate.client_instruction(("blob", "3", "x")) is True             # stream closed; id may be reused
    assert gate.client_instruction(("mouse", "1", "2", "0", "0")) is True
    summary = gate.summary()
    assert summary["clipboard_policy"] == "blocked" and summary["browser_to_remote_transfers"] == 1
    assert summary["blocked_at_gateway"] == 1 and summary["content_captured"] is False
    assert secret not in repr(summary)


def test_allowed_gate_forwards_and_counts_both_directions():
    gate = ClipboardGate(allowed=True)
    assert gate.client_instruction(("clipboard", "1", "text/plain")) is True
    assert gate.client_instruction(("blob", "1", "eA==")) is True
    gate.server_instruction(("clipboard", "2", "text/plain"))
    gate.server_instruction(("sync", "10"))
    s = gate.summary()
    assert s["clipboard_policy"] == "allowed" and s["browser_to_remote_transfers"] == 1
    assert s["blocked_at_gateway"] == 0 and s["remote_to_browser_transfers"] == 1


def test_no_activity_means_no_audit_event():
    assert ClipboardGate(False).summary() is None
    assert encode("clipboard", "1", "text/plain")  # the codec used by the relay is importable here


def test_client_name_is_the_session_number_and_is_safe():
    assert client_name("SES-8D133") == "SES-8D133"
    assert client_name("ses-8d133") == "SES-8D133"
    assert client_name("SES-8D133;rm -rf /\n") == "SES-8D133RM-RF"[:15]
    assert len(client_name("SES-" + "A" * 40)) == 15
    assert client_name(None) == client_name("") == "SECUREPAM"
