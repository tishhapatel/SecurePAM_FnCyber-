"""
Lab OpenBao integration: OPENBAO_TOKEN_FILE loading (fail closed, never
echoed) and a drift guard keeping infrastructure/openbao's runtime policy
least-privilege and aligned with the path rules the backend enforces.
"""

import re
from pathlib import Path

import pytest

from app.core.config import BACKEND_DIR, Settings, SettingsError
from app.secret_providers.paths import validate_secret_path

REPO = BACKEND_DIR.parent
POLICY = REPO / "infrastructure/openbao/policies/securepam-runtime.hcl"
INIT = REPO / "infrastructure/openbao/init-lab.sh"
CANARY = "s.FILETOKENCANARY0123456789"


def make(**kw) -> Settings:
    return Settings(_env_file=None, SECRET_PROVIDER="openbao", OPENBAO_ADDR="http://127.0.0.1:8200", **kw)


# --- OPENBAO_TOKEN_FILE -------------------------------------------------------

def test_token_loaded_from_file_and_stripped(tmp_path):
    f = tmp_path / "app-token"
    f.write_text(f"{CANARY}\n")
    s = make(OPENBAO_TOKEN_FILE=str(f))
    assert s.OPENBAO_TOKEN.get_secret_value() == CANARY
    assert CANARY not in repr(s) and CANARY not in str(s.model_dump())


@pytest.mark.parametrize("content, message", [("", "OPENBAO_TOKEN is required"), ("  \n", "OPENBAO_TOKEN is required"),
                                              ("s.has space", "whitespace or non-printable")])
def test_bad_token_file_contents_fail_closed(tmp_path, content, message):
    f = tmp_path / "app-token"
    f.write_text(content)
    with pytest.raises(SettingsError, match=message):
        make(OPENBAO_TOKEN_FILE=str(f))


def test_missing_token_file_fails_closed(tmp_path):
    with pytest.raises(SettingsError, match="OPENBAO_TOKEN_FILE could not be read"):
        make(OPENBAO_TOKEN_FILE=str(tmp_path / "does-not-exist"))


def test_unreadable_token_file_fails_closed(tmp_path):
    f = tmp_path / "app-token"
    f.write_text(CANARY)
    f.chmod(0o000)
    try:
        with pytest.raises(SettingsError) as exc:
            make(OPENBAO_TOKEN_FILE=str(f))
        assert CANARY not in str(exc.value)
    finally:
        f.chmod(0o600)


def test_token_and_token_file_together_refused(tmp_path):
    f = tmp_path / "app-token"
    f.write_text(CANARY)
    with pytest.raises(SettingsError, match="Set only one"):
        make(OPENBAO_TOKEN="other", OPENBAO_TOKEN_FILE=str(f))


def test_token_file_ignored_for_mock_provider(tmp_path):
    s = Settings(_env_file=None, SECRET_PROVIDER="mock", OPENBAO_TOKEN_FILE=str(tmp_path / "nope"))
    assert s.SECRET_PROVIDER == "mock"


# --- runtime policy drift guard -----------------------------------------------

def _policy_rules() -> dict[str, list[str]]:
    text = re.sub(r"#.*", "", POLICY.read_text())
    rules = {}
    for path, body in re.findall(r'path\s+"([^"]+)"\s*\{(.*?)\}', text, re.S):
        caps = re.search(r"capabilities\s*=\s*\[(.*?)\]", body, re.S).group(1)
        rules[path] = re.findall(r'"([^"]+)"', caps)
    return rules


def test_runtime_policy_is_read_only_on_asset_data_path():
    assert _policy_rules() == {"secret/data/securepam/assets/*": ["read"]}


def test_runtime_policy_matches_backend_path_rules():
    (path,) = _policy_rules()
    mount, _, rest = path.partition("/data/")
    assert mount == "secret"
    validate_secret_path(rest.replace("*", "example"), "securepam")


def test_lab_sample_secret_is_at_a_path_the_backend_accepts():
    m = re.search(r'bao kv put "secret/\$\{SECRET_PREFIX\}/(assets/[a-z0-9-]+)"', INIT.read_text())
    assert m, "init-lab.sh no longer writes the sample under <prefix>/assets/"
    validate_secret_path(f"securepam/{m.group(1)}", "securepam")


def test_init_script_never_prints_the_token():
    script = INIT.read_text()
    assert "-field=token" in script and '> "$tmp"' in script  # token goes to the file, not stdout
    for line in script.splitlines():
        if re.match(r"\s*(echo|printf)\b", line):
            assert not re.search(r"\$\{?BAO_TOKEN", line), line  # never expands the root token
    assert not re.search(r"\bcat\b[^\n]*app-token", script)
