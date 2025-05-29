import glob
import shutil

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
    print("= check unicode= ")
    session.run("python", "tools/check_unicode.py")
    print("\n= cython-lint= ")
    session.run("cython-lint", "cydrogen")
    print("\n= ruff =")
    session.run("ruff", "check")
    print("\n= ruff format =")
    session.run("ruff", "format", "--check")
    print("\n= mypi =")
    session.run("mypy", "--pretty", "--no-color-output", "cydrogen")
    session.run("mypy", "--pretty", "--no-color-output", "tests")
    print("\n= shellcheck =")
    if shutil.which("shellcheck") is None:
        print("===> shellcheck not found, skipping")
    else:
        bash_files = glob.glob("**/*.sh", recursive=True)
        if not bash_files:
            print("no bash files found")
        else:
            for bash_file in bash_files:
                print(f"- checking {bash_file}")
                session.run("shellcheck", bash_file, external=True)
    print("\n= actionlint =")
    if shutil.which("actionlint") is None:
        print("===> actionlint not found, skipping")
    else:
        session.run("actionlint", "-verbose", external=True)
    print("\n= zizmor =")
    session.run("zizmor", "--no-progress", ".")
    if shutil.which("typos") is None:
        print("===> typos not found, skipping")
    else:
        print("\n= typos =")
        session.run("typos", external=True)


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def test(session: nox.Session):
    print("\n=== tests ===\n")
    session.install(*nox.project.dependency_groups(PYPROJECT, "test"))
    session.install(".")
    session.run("pytest")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def build(session: nox.Session):
    print("\n=== build ===\n")
    session.run("rm", "-rf", "dist", external=True)
    session.install(*nox.project.dependency_groups(PYPROJECT, "build"))
    session.run("python", "-m", "build", "--sdist", "--wheel")
    print("\n= twine check =")
    session.run("twine", "check", "dist/*")
    print("\n= check symbols =")
    if shutil.which("nm") is None:
        print("===> nm not found, skipping")
    session.run("python", "tools/check_pyext_symbol_hiding.py", "dist")
