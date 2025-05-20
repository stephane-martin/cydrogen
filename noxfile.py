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
    print()
    session.install(*nox.project.dependency_groups(PYPROJECT, "develop"))
    print("\n=== linters ===\n")
    print("check unicode")
    session.run("python", "tools/check_unicode.py")
    print("\ncython-lint")
    session.run("cython-lint", "cydrogen")
    print("\nruff")
    session.run("ruff", "check")
    print("\nruff format")
    session.run("ruff", "format", "--check")
    print("\nmypi")
    session.run("mypy", "cydrogen")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def test(session: nox.Session):
    print("\n=== tests ===\n")
    session.install(*nox.project.dependency_groups(PYPROJECT, "test"))
    session.install(".[test]")
    session.run("pytest")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def build(session: nox.Session):
    print("\n=== build ===\n")
    session.run("rm", "-rf", "dist", external=True)
    session.install(*nox.project.dependency_groups(PYPROJECT, "build"))
    session.run("python", "-m", "build", "--sdist", "--wheel")
    print("\n check wheels using twine")
    session.run("twine", "check", "dist/*")
