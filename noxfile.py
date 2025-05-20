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
    session.run("cython-lint", "cydrogen")
    session.run("ruff", "check")
    session.run("ruff", "format", "--check")
    session.run("mypy", "cydrogen")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def test(session: nox.Session):
    session.install("build >= 0.11.0")
    session.install(".[test]")
    session.run("pytest")
