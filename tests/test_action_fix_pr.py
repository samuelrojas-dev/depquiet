"""The Action's fix pull request: real git against a local remote, gh stubbed."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests.test_action import _outputs, _run_step, _step, shell_env  # noqa: F401

TOKEN = "tok123"
URL = f"https://x-access-token:{TOKEN}@github.com/owner/repository.git"


def _git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env=env, check=True)
    return r.stdout.strip()


@pytest.fixture
def repo(tmp_path, shell_env):  # noqa: F811
    """A clone with a project in a subfolder, whose pushes go to a local bare remote."""
    bash, env = shell_env
    if os.name == "nt":
        pytest.skip("file remotes with insteadOf are exercised on POSIX only")
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    _git(work, "config", "user.email", "t@example.com")
    _git(work, "config", "user.name", "t")
    project = work / "apps" / "client portal"
    project.mkdir(parents=True)
    (project / "pyproject.toml").write_text('dependencies = ["requests==2.31.0"]\n')
    (project / "uv.lock").write_text('name = "requests"\nversion = "2.31.0"\n')
    (project / "notes.txt").write_text("keep me\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "base")
    config = tmp_path / "gitconfig"
    config.write_text(f'[url "file://{remote}"]\n\tinsteadOf = {URL}\n')
    gh = tmp_path / "gh_fix.py"
    gh.write_text(
        "import json, os, sys\n"
        "a = sys.argv[1:]\n"
        "open(os.environ['GH_CALLS'], 'a').write(json.dumps(a) + '\\n')\n"
        "if a[:2] == ['pr', 'list']: print(os.environ.get('EXISTING_PR', ''))\n"
        "elif a[:2] == ['pr', 'create']: print('https://github.com/owner/repository/pull/7')\n"
        "elif a[:2] == ['pr', 'view']: print('https://github.com/owner/repository/pull/5')\n"
    )
    report = tmp_path / "fix-pr.md"
    report.write_text("## Security fixes verified by depquiet\n")
    env.update(
        GH_STUB=gh.as_posix(),
        GIT_CONFIG_GLOBAL=config.as_posix(),
        GH_TOKEN=TOKEN,
        GITHUB_REF_TYPE="branch",
        GITHUB_REF_NAME="main",
        GITHUB_SERVER_URL="https://github.com",
        INPUT_FIX_PR_BRANCH="depquiet/security-fixes",
        FIX_REPORT=report.as_posix(),
        INPUT_PATH=project.as_posix(),
    )
    return work, project, remote, report, (bash, env)


def _apply(project: Path) -> None:
    (project / "pyproject.toml").write_text('dependencies = ["requests==2.33.0"]\n')
    (project / "uv.lock").write_text('name = "requests"\nversion = "2.33.0"\n')
    (project / "notes.txt").write_text("unrelated local change\n")
    (project / "scratch.toml").write_text("untracked\n")


def _gh_calls(env: dict[str, str]) -> list[list[str]]:
    path = Path(env["GH_CALLS"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_opens_a_pull_request_with_only_the_plan_files(repo) -> None:
    work, project, remote, report, shell = repo
    _apply(project)
    result = _run_step("Open fix pull request", shell)
    assert result.returncode == 0, result.stderr
    pushed = _git(remote, "show", "--name-only", "--format=%s", "depquiet/security-fixes")
    assert pushed.splitlines()[0] == "fix(deps): security fixes verified by depquiet"
    assert sorted(pushed.splitlines()[2:]) == [
        "apps/client portal/pyproject.toml",
        "apps/client portal/uv.lock",
    ]
    create = next(c for c in _gh_calls(shell[1]) if c[:2] == ["pr", "create"])
    assert create[create.index("--base") + 1] == "main"
    assert create[create.index("--body-file") + 1] == report.as_posix()
    assert _outputs(shell[1])["url"] == "https://github.com/owner/repository/pull/7"
    # The checkout is back on the base commit; unrelated changes are untouched.
    assert _git(work, "log", "-1", "--format=%s") == "base"
    assert (project / "scratch.toml").exists()
    assert TOKEN not in result.stdout + result.stderr


def test_updates_the_open_pull_request_instead_of_opening_another(repo) -> None:
    _, project, _, _, shell = repo
    shell[1]["EXISTING_PR"] = "5"
    _apply(project)
    result = _run_step("Open fix pull request", shell)
    assert result.returncode == 0, result.stderr
    calls = _gh_calls(shell[1])
    assert any(c[:3] == ["pr", "edit", "5"] for c in calls)
    assert not any(c[:2] == ["pr", "create"] for c in calls)
    assert _outputs(shell[1])["url"].endswith("/pull/5")


def test_no_report_means_no_push_and_no_pull_request(repo) -> None:
    _, project, remote, report, shell = repo
    report.write_text("")
    _apply(project)
    result = _run_step("Open fix pull request", shell)
    assert result.returncode == 0
    assert _git(remote, "branch", "--list") == ""
    assert _gh_calls(shell[1]) == []


def test_nothing_changed_means_no_pull_request(repo) -> None:
    _, _, remote, _, shell = repo
    result = _run_step("Open fix pull request", shell)
    assert result.returncode == 0
    assert _git(remote, "branch", "--list") == ""


def test_refuses_to_push_to_the_base_branch(repo) -> None:
    _, project, remote, _, shell = repo
    shell[1]["INPUT_FIX_PR_BRANCH"] = "main"
    _apply(project)
    result = _run_step("Open fix pull request", shell)
    assert result.returncode == 2
    assert _git(remote, "branch", "--list") == ""


@pytest.mark.parametrize("event", ["pull_request", "pull_request_target"])
def test_run_step_never_applies_on_pull_request_events(shell_env, event) -> None:  # noqa: F811
    _, env = shell_env
    env.update(INPUT_FIX_PR="true", GITHUB_EVENT_NAME=event, SCAN_EXIT="0")
    result = _run_step("Run depquiet", shell_env)
    assert result.returncode == 0
    args = json.loads(Path(env["CALLS"]).read_text().splitlines()[0])
    assert "--apply" not in args and "--fix-plan" not in args
    assert "fix_report" not in _outputs(env)


def test_run_step_applies_the_plan_on_a_schedule(shell_env) -> None:  # noqa: F811
    _, env = shell_env
    env.update(INPUT_FIX_PR="true", GITHUB_EVENT_NAME="schedule", SCAN_EXIT="0")
    _run_step("Run depquiet", shell_env)
    args = json.loads(Path(env["CALLS"]).read_text().splitlines()[0])
    assert "--apply" in args and "--fix-plan-report" in args
    assert _outputs(env)["fix_report"].endswith("fix-pr.md")


def test_fix_pr_step_is_guarded() -> None:
    block, _ = _step("Open fix pull request")
    assert "inputs.fix-pr == 'true'" in block and "steps.run.outputs.fix_report != ''" in block
