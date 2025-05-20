import nox

nox.options.reuse_existing_virtualenvs = True
nox.options.error_on_missing_interpreters = True

PYPROJECT = nox.project.load_toml("pyproject.toml")
SUPPORTED_PYTHON_VERSIONS = nox.project.python_versions(PYPROJECT)


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def develop(session: nox.Session):
    session.install(*nox.project.dependency_groups(PYPROJECT, "develop"))
    session.run("pre-commit", "install")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def lint(session: nox.Session):
    session.install(*nox.project.dependency_groups(PYPROJECT, "develop"))
    print("check unicode")
    session.run("python", "tools/check_unicode.py")
    print()
    print("cython-lint")
    session.run("cython-lint", "cydrogen")
    print()
    print("ruff")
    session.run("ruff", "check")
    print()
    print("ruff format")
    session.run("ruff", "format", "--check")
    print()
    print("mypi")
    session.run("mypy", "cydrogen")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def test(session: nox.Session):
    session.install("build >= 0.11.0")
    session.install(".[test]")
    session.run("pytest")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def build(session: nox.Session):
    session.run("rm", "-rf", "dist")
    session.install("build >= 0.11.0")
    session.run("python", "-m", "build", "--sdist", "--wheel")
    session.run("twine", "check", "dist/*")
