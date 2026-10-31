import os

import pytest

from v6race.server import transparent_listener


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="Linux, unprivileged only")
def test_transparent_listener_fails_only_for_lack_of_privilege():
    with pytest.raises(PermissionError):
        transparent_listener(0)


def test_config_validation_refuses_dangerous_values(tmp_path):
    from v6race import config
    f = tmp_path / "c.toml"
    for bad in ("route_table = 254", "intercept_mark = 0x7673", "waves = 0", "port = 70000", 'v4_only = "x.com"'):
        f.write_text(bad + "\n")
        with pytest.raises(ValueError):
            config.load(f)
    f.write_text("wave_size = 6\n")
    assert config.load(f).wave_size == 6


def test_cleanup_removes_only_what_v6race_added(monkeypatch):
    from v6race import cleanup
    calls = []

    class R:
        def __init__(self, rc=0, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    rules_left = {tuple(s[2:]) for s in cleanup.rule_specs(cleanup.DEFAULTS)}

    def fake_run(args, stdin=None):
        calls.append(args)
        if args[:3] == ["nft", "delete", "table"]:
            return R(1, err="Error: No such file or directory")
        if args[2:4] == ["rule", "del"]:
            key = tuple(args[4:])
            if key in rules_left:
                rules_left.discard(key)
                return R()
            return R(2, err="RTNETLINK answers: No such file or directory")
        if args[2:4] == ["route", "show"]:
            return R(out="local default dev lo metric 1024 pref medium\nlocal default dev wlp8s0 metric 100 pref medium\n")
        if args[2:4] == ["route", "del"]:
            return R()
        return R(1, err="unexpected")

    monkeypatch.setattr(cleanup, "_run", fake_run)
    monkeypatch.setattr(cleanup, "STATE_PATH", __import__("pathlib").Path("/nonexistent/rules.json"))
    assert cleanup.down(cleanup.load_params()) == []          # "already gone" isn't an error
    assert not rules_left                                      # every rule removed
    deleted = [a for a in calls if a[2:4] == ["route", "del"]]
    assert {a[a.index("dev") + 1] for a in deleted} == {"lo", "wlp8s0"}
    assert not any("flush" in a for a in calls)                # never empties the whole table
