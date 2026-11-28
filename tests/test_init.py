"""Tests for v0.25.0 ``depquiet init`` config scaffolder.

Covers: project detection (package manager, CI, scanner signals),
config generation, overwrite protection, --yes mode, --force mode,
--output flag, and CLI dispatch.
"""

from __future__ import annotations

from pathlib import Path

from depquiet.init import (
    ProjectInfo,
    detect_project,
    generate_config,
    init_command,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------


class TestDetectPackageManagers:
    def test_npm(self, tmp_path: Path):
        _touch(tmp_path / "package.json")
        info = detect_project(tmp_path)
        assert "npm" in info.package_managers

    def test_pip_requirements(self, tmp_path: Path):
        _touch(tmp_path / "requirements.txt")
        info = detect_project(tmp_path)
        assert "pip" in info.package_managers

    def test_pip_pyproject(self, tmp_path: Path):
        _touch(tmp_path / "pyproject.toml")
        info = detect_project(tmp_path)
        assert "pip" in info.package_managers

    def test_go(self, tmp_path: Path):
        _touch(tmp_path / "go.mod")
        info = detect_project(tmp_path)
        assert "go" in info.package_managers

    def test_cargo(self, tmp_path: Path):
        _touch(tmp_path / "Cargo.toml")
        info = detect_project(tmp_path)
        assert "cargo" in info.package_managers

    def test_maven(self, tmp_path: Path):
        _touch(tmp_path / "pom.xml")
        info = detect_project(tmp_path)
        assert "maven" in info.package_managers

    def test_gradle(self, tmp_path: Path):
        _touch(tmp_path / "build.gradle")
        info = detect_project(tmp_path)
        assert "gradle" in info.package_managers

    def test_gradle_kts(self, tmp_path: Path):
        _touch(tmp_path / "build.gradle.kts")
        info = detect_project(tmp_path)
        assert "gradle" in info.package_managers

    def test_gem(self, tmp_path: Path):
        _touch(tmp_path / "Gemfile")
        info = detect_project(tmp_path)
        assert "gem" in info.package_managers

    def test_composer(self, tmp_path: Path):
        _touch(tmp_path / "composer.json")
        info = detect_project(tmp_path)
        assert "composer" in info.package_managers

    def test_pub(self, tmp_path: Path):
        _touch(tmp_path / "pubspec.yaml")
        info = detect_project(tmp_path)
        assert "pub" in info.package_managers

    def test_nuget_csproj(self, tmp_path: Path):
        _touch(tmp_path / "MyApp.csproj")
        info = detect_project(tmp_path)
        assert "nuget" in info.package_managers

    def test_multiple_managers(self, tmp_path: Path):
        _touch(tmp_path / "package.json")
        _touch(tmp_path / "pyproject.toml")
        info = detect_project(tmp_path)
        assert "npm" in info.package_managers
        assert "pip" in info.package_managers

    def test_empty_project(self, tmp_path: Path):
        info = detect_project(tmp_path)
        assert info.package_managers == []


class TestDetectCI:
    def test_github_actions(self, tmp_path: Path):
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        info = detect_project(tmp_path)
        assert "github-actions" in info.ci_providers

    def test_gitlab_ci(self, tmp_path: Path):
        _touch(tmp_path / ".gitlab-ci.yml")
        info = detect_project(tmp_path)
        assert "gitlab-ci" in info.ci_providers

    def test_jenkins(self, tmp_path: Path):
        _touch(tmp_path / "Jenkinsfile")
        info = detect_project(tmp_path)
        assert "jenkins" in info.ci_providers

    def test_circleci(self, tmp_path: Path):
        (tmp_path / ".circleci").mkdir()
        info = detect_project(tmp_path)
        assert "circleci" in info.ci_providers

    def test_bitbucket(self, tmp_path: Path):
        _touch(tmp_path / "bitbucket-pipelines.yml")
        info = detect_project(tmp_path)
        assert "bitbucket" in info.ci_providers

    def test_azure_devops(self, tmp_path: Path):
        _touch(tmp_path / "azure-pipelines.yml")
        info = detect_project(tmp_path)
        assert "azure-devops" in info.ci_providers

    def test_no_ci(self, tmp_path: Path):
        info = detect_project(tmp_path)
        assert info.ci_providers == []


class TestDetectScanners:
    def test_snyk(self, tmp_path: Path):
        _touch(tmp_path / ".snyk")
        info = detect_project(tmp_path)
        assert "snyk" in info.existing_scanners

    def test_trivy(self, tmp_path: Path):
        _touch(tmp_path / "trivy.yaml")
        info = detect_project(tmp_path)
        assert "trivy" in info.existing_scanners

    def test_grype(self, tmp_path: Path):
        _touch(tmp_path / ".grype.yaml")
        info = detect_project(tmp_path)
        assert "grype" in info.existing_scanners

    def test_osv_scanner(self, tmp_path: Path):
        _touch(tmp_path / ".osv-scanner.toml")
        info = detect_project(tmp_path)
        assert "osv-scanner" in info.existing_scanners

    def test_dependabot(self, tmp_path: Path):
        _touch(tmp_path / ".github" / "dependabot.yml")
        info = detect_project(tmp_path)
        assert "dependabot" in info.existing_scanners

    def test_renovate(self, tmp_path: Path):
        _touch(tmp_path / "renovate.json")
        info = detect_project(tmp_path)
        assert "renovate" in info.existing_scanners


class TestDetectExistingConfig:
    def test_yaml_extension(self, tmp_path: Path):
        _touch(tmp_path / ".depquiet.yaml")
        info = detect_project(tmp_path)
        assert info.has_depquiet_config is True

    def test_yml_extension(self, tmp_path: Path):
        _touch(tmp_path / ".depquiet.yml")
        info = detect_project(tmp_path)
        assert info.has_depquiet_config is True

    def test_no_config(self, tmp_path: Path):
        info = detect_project(tmp_path)
        assert info.has_depquiet_config is False


# ---------------------------------------------------------------------------
# Config generation tests
# ---------------------------------------------------------------------------


class TestGenerateConfig:
    def test_basic_config_has_required_keys(self):
        info = ProjectInfo()
        text = generate_config(info)
        assert "epss_threshold:" in text
        assert "fail_on:" in text
        assert "kev: true" in text

    def test_github_actions_enables_sarif(self):
        info = ProjectInfo(ci_providers=["github-actions"])
        text = generate_config(info)
        assert "sarif:" in text
        assert "summary:" in text

    def test_no_ci_no_sarif(self):
        info = ProjectInfo()
        text = generate_config(info)
        assert "sarif:" not in text

    def test_explicit_sarif_flag(self):
        info = ProjectInfo()
        text = generate_config(info, sarif=True)
        assert "sarif:" in text

    def test_existing_scanners_noted(self):
        info = ProjectInfo(existing_scanners=["snyk", "trivy"])
        text = generate_config(info)
        assert "snyk" in text
        assert "trivy" in text
        assert "Detected existing scanners" in text

    def test_header_present(self):
        info = ProjectInfo()
        text = generate_config(info)
        assert "# depquiet configuration" in text
        assert "depquiet init" in text

    def test_always_flag_commented_example(self):
        info = ProjectInfo()
        text = generate_config(info)
        assert "# always_flag:" in text

    def test_ends_with_newline(self):
        info = ProjectInfo()
        text = generate_config(info)
        assert text.endswith("\n")


# ---------------------------------------------------------------------------
# init_command integration tests
# ---------------------------------------------------------------------------


class TestInitCommand:
    def test_creates_config_non_interactive(self, tmp_path: Path):
        _touch(tmp_path / "package.json")
        rc = init_command(tmp_path, yes=True)
        assert rc == 0
        assert (tmp_path / ".depquiet.yaml").is_file()

    def test_config_is_valid_yaml(self, tmp_path: Path):
        """The generated config should be loadable by our own parser."""
        from depquiet.config import load_config

        rc = init_command(tmp_path, yes=True)
        assert rc == 0
        config = load_config(tmp_path)
        assert config.fail_on == "high"
        assert config.kev is True

    def test_refuses_overwrite_without_force(self, tmp_path: Path):
        _touch(tmp_path / ".depquiet.yaml")
        rc = init_command(tmp_path, yes=True)
        assert rc == 1

    def test_force_overwrites(self, tmp_path: Path):
        existing = tmp_path / ".depquiet.yaml"
        existing.write_text("old config\n", encoding="utf-8")
        rc = init_command(tmp_path, yes=True, force=True)
        assert rc == 0
        text = existing.read_text(encoding="utf-8")
        assert "old config" not in text
        assert "epss_threshold" in text

    def test_custom_output_path(self, tmp_path: Path):
        out = tmp_path / "custom" / "my-config.yaml"
        rc = init_command(tmp_path, yes=True, output=out)
        assert rc == 0
        assert out.is_file()
        assert "epss_threshold" in out.read_text(encoding="utf-8")

    def test_github_actions_detected_in_output(self, tmp_path: Path):
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        rc = init_command(tmp_path, yes=True)
        assert rc == 0
        text = (tmp_path / ".depquiet.yaml").read_text(encoding="utf-8")
        assert "sarif:" in text

    def test_existing_scanner_noted(self, tmp_path: Path):
        _touch(tmp_path / ".snyk")
        rc = init_command(tmp_path, yes=True)
        assert rc == 0
        text = (tmp_path / ".depquiet.yaml").read_text(encoding="utf-8")
        assert "snyk" in text


# ---------------------------------------------------------------------------
# CLI dispatch tests
# ---------------------------------------------------------------------------


class TestCLIDispatch:
    def test_init_subcommand(self, tmp_path: Path):
        from depquiet.cli import main

        rc = main(["init", "--path", str(tmp_path), "--yes"])
        assert rc == 0
        assert (tmp_path / ".depquiet.yaml").is_file()

    def test_init_force(self, tmp_path: Path):
        from depquiet.cli import main

        _touch(tmp_path / ".depquiet.yaml")
        rc = main(["init", "--path", str(tmp_path), "--yes", "--force"])
        assert rc == 0

    def test_init_output(self, tmp_path: Path):
        from depquiet.cli import main

        out = tmp_path / "out.yaml"
        rc = main(["init", "--path", str(tmp_path), "--yes", "-o", str(out)])
        assert rc == 0
        assert out.is_file()


def test_init_refuses_a_missing_project_directory(tmp_path):
    missing = tmp_path / "typo"
    assert init_command(missing, yes=True) == 2
    assert not missing.exists()


def test_a_poetry_or_uv_project_is_named_by_its_lock(tmp_path) -> None:
    """End-to-end review (2026-11-27): init said "Package managers: pip" on a Poetry project."""
    from depquiet.init import detect_project

    (tmp_path / "pyproject.toml").write_text("[tool.poetry]\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")
    assert detect_project(tmp_path).package_managers == ["poetry"]
    (tmp_path / "poetry.lock").unlink()
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    assert detect_project(tmp_path).package_managers == ["uv"]
