import nox

nox.options.reuse_existing_virtualenvs = True
nox.options.error_on_missing_interpreters = True

SUPPORTED_PYTHON_VERSIONS = ("3.12", "3.13")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def develop(session: nox.Session):
    pyproject = nox.project.load_toml("pyproject.toml")
    session.install(*nox.project.dependency_groups(pyproject, "develop"))
    session.run("pre-commit", "install")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def lint(session: nox.Session):
    pyproject = nox.project.load_toml("pyproject.toml")
    session.install(*nox.project.dependency_groups(pyproject, "develop"))
    session.run("cython-lint", "cydrogen")
    session.run("ruff", "check")
    session.run("ruff", "format", "--check")
    session.run("mypy", "cydrogen")
