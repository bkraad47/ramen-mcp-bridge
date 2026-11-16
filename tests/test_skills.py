"""`ramen-mcp-bridge skills list|install` (bridge 0.6.0, CONTRACTS §33.2) against the fake worker, in a temp HOME."""

import base64
import json
import stat

import pytest
from test_bridge import fake, make_bridge, run  # noqa: F401 - fixture
from test_policy import TARGET, home  # noqa: F401 - fixture
from test_scan import SS, fake_ss  # noqa: F401 - fixture
from test_telemetry import CFG

from ramen_mcp_bridge import bridge, clients, policy, skills

SKILL_MD = "---\nname: noodle-math\ndescription: adds noodles\n---\n# Noodle math\n"
NOODLE = {
    "name": "noodle-math",
    "description": "adds noodles",
    "version": "a1b2c3d4e5f6",
    "files": ["SKILL.md", "scripts/run.py", "img.bin"],
}
IRIS = {"name": "iris-analyst", "description": "iris", "version": "0123456789ab", "files": ["SKILL.md"]}


@pytest.fixture
def served(fake):  # noqa: F811
    fake.skills = [NOODLE, IRIS]
    fake.skill_files = {
        "skill://noodle-math/SKILL.md": {"text": SKILL_MD},
        "skill://noodle-math/scripts/run.py": {"text": "print('hi')\n"},
        "skill://noodle-math/img.bin": {"blob": base64.b64encode(b"\x00\x01\x02").decode()},
        "skill://iris-analyst/SKILL.md": {"text": "---\nname: iris-analyst\n---\n"},
    }
    return fake


def flags(fake):  # noqa: F811
    return ["--target", fake.target, "--insecure", "--key", "good", "--group", "demo", "--zone", "local"]


def ledger():
    try:
        return json.loads(clients.ledger_path().read_text())["entries"]
    except OSError:
        return []


def test_list_goes_through_the_bridge_and_prints_the_skills(home, served, capsys):  # noqa: F811
    assert bridge.main(["skills", "list", *flags(served)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("noodle-math\ta1b2c3d4e5f6\t3 files\tadds noodles") and out[1].startswith("iris-analyst\t")
    assert served.seen[-1]["authorization"] == "Bearer good" and served.seen[-1]["ramen-group"] == "demo"
    served.skills = None  # an older worker: method not found is an error, not a crash
    assert bridge.main(["skills", "list", *flags(served)]) == 1
    assert "method not found" in capsys.readouterr().err


def test_install_writes_the_files_records_them_and_policy_remove_deletes_them(home, served, capsys):  # noqa: F811
    dest = home / "skills"
    assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 0
    d = dest / "noodle-math"
    assert (d / "SKILL.md").read_text() == SKILL_MD and (d / "scripts" / "run.py").read_text() == "print('hi')\n"
    assert (d / "img.bin").read_bytes() == b"\x00\x01\x02"
    for p in (d / "SKILL.md", d / "scripts" / "run.py", d / "img.bin"):
        assert stat.S_IMODE(p.stat().st_mode) == 0o644
    assert not list(dest.glob(".ramen-skill-*"))  # the staging directory is gone
    err = capsys.readouterr().err
    assert f"wrote {d / 'SKILL.md'}" in err and "installed skill noodle-math" in err
    entries = ledger()
    assert len(entries) == 3 and all(
        e["kind"] == "skill"
        and e["key"] == "noodle-math"
        and (e["target"], e["group"], e["zone"]) == (served.target, "demo", "local")
        for e in entries
    )
    # the default directory is ~/.claude/skills
    assert bridge.main(["skills", "install", "iris-analyst", *flags(served)]) == 0
    assert (home / ".claude" / "skills" / "iris-analyst" / "SKILL.md").is_file() and len(ledger()) == 4
    # installing again replaces what Ramen wrote; a directory Ramen did not write is refused
    served.skill_files["skill://noodle-math/SKILL.md"] = {"text": "# v2\n"}
    assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 0
    assert (d / "SKILL.md").read_text() == "# v2\n" and len(ledger()) == 4
    (dest / "mine").mkdir()
    served.skills = [*served.skills, {"name": "mine", "files": ["SKILL.md"]}]
    served.skill_files["skill://mine/SKILL.md"] = {"text": "x"}
    assert bridge.main(["skills", "install", "mine", "--dir", str(dest), *flags(served)]) == 1
    assert "not installed by Ramen" in capsys.readouterr().err and not (dest / "mine" / "SKILL.md").exists()
    # policy remove (a bundle exists for this target/group/zone) deletes every file and the emptied directories
    pol = policy.Policy(served.target, "demo", "local", "https://console.example")
    pol.update(CFG, None)
    assert bridge.main(["policy", "remove"]) == 0
    assert not d.exists() and not (home / ".claude" / "skills" / "iris-analyst").exists()
    assert dest.is_dir() and (dest / "mine").is_dir()  # what Ramen did not create stays
    assert ledger() == [] and "reverted skill" in capsys.readouterr().err


def test_hostile_paths_oversize_and_unknown_skills_write_nothing(home, served, capsys):  # noqa: F811
    dest = home / "skills"
    for bad in ("../evil.md", "/etc/passwd", "a/../../b", "a//b", "", "a\\b", "./x"):
        served.skills = [{"name": "noodle-math", "files": ["SKILL.md", bad]}]
        assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 1, bad
        assert "path refused" in capsys.readouterr().err
    served.skills = [NOODLE]
    served.skill_files["skill://noodle-math/img.bin"] = {"text": "x" * (skills.MAX_FILE + 1)}
    assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 1
    assert "over the 256 KiB limit" in capsys.readouterr().err
    served.skill_files["skill://noodle-math/img.bin"] = {"blob": "not base64!"}
    assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 1
    served.skill_files["skill://noodle-math/img.bin"] = {}
    assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 1
    assert bridge.main(["skills", "install", "nope", "--dir", str(dest), *flags(served)]) == 1
    assert "does not serve it" in capsys.readouterr().err
    assert bridge.main(["skills", "install", "../x", "--dir", str(dest), *flags(served)]) == 1
    assert not dest.exists() or not any(dest.iterdir())
    assert ledger() == []
    with pytest.raises(SystemExit):
        bridge.main(["skills", "install", *flags(served)])  # the name is required


def test_a_required_scan_runs_first_and_do_not_install_writes_nothing(home, served, fake_ss, capsys, monkeypatch):  # noqa: F811
    dest = home / "skills"
    pol = policy.Policy(served.target, "demo", "local", "https://console.example")
    pol.update(CFG, None, {**SS, "baseline": ""})
    b = make_bridge(served)
    b.policy = pol
    # blocked: nothing under dest, exit 3, the block line
    fake_ss.verdict("DO_NOT_INSTALL")
    with pytest.raises(skills.SkillError) as e:
        skills.install(b, pol, "noodle-math", dest, served.target, "demo", "local")
    assert e.value.code == 3 and not (dest / "noodle-math").exists() and not list(dest.glob(".ramen-skill-*"))
    (call,) = fake_ss.calls()
    assert call[0] == "scan" and "--recursive" in call and "--no-llm" in call and call[1].startswith(str(dest))
    assert ledger() == []
    # caution: written, said
    fake_ss.verdict("CAUTION")
    written = skills.install(b, pol, "noodle-math", dest, served.target, "demo", "local")
    assert len(written) == 3 and (dest / "noodle-math" / "SKILL.md").is_file()
    assert "noodle-math: CAUTION" in capsys.readouterr().err
    # a baseline in the bundle: the staged skill is scanned on its own with --baseline
    pol.update(CFG, None, {**SS, "baseline": "rules: []\n"})
    fake_ss.verdict("SAFE")
    skills.install(b, pol, "iris-analyst", dest, served.target, "demo", "local")
    last = fake_ss.calls()[-1]
    assert "--baseline" in last and last[1].endswith("/iris-analyst") and "--recursive" not in last
    # no scanner on PATH while required: blocked with the install hint
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(skills.SkillError) as e:
        skills.install(b, pol, "noodle-math", dest, served.target, "demo", "local")
    assert e.value.code == 3 and "uv tool install" in capsys.readouterr().err
    # through the CLI the exit code and the policy line reach the person (a static key: no bundle, no scan)
    assert bridge.main(["skills", "install", "noodle-math", "--dir", str(dest), *flags(served)]) == 0


def test_safe_rel_and_valid_name():
    assert skills.safe_rel("a/b.c") == "a/b.c" and skills.safe_rel("SKILL.md") == "SKILL.md"
    for bad in (None, "", "/a", "../a", "a/..", "a/./b", "a\\b", "a\x00b", "a//b"):
        assert skills.safe_rel(bad) is None, bad
    assert skills.valid_name("iris-analyst") and skills.valid_name("a_1")
    for bad in (None, "", "a.b", "a/b", "x" * 65, "-"):
        assert skills.valid_name(bad) is (bad == "-"), bad
