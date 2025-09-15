import pathlib
import shutil

import nox

nox.options.reuse_existing_virtualenvs = True
nox.options.error_on_missing_interpreters = True

PYPROJECT = nox.project.load_toml("pyproject.toml")
SUPPORTED_PYTHON_VERSIONS = nox.project.python_versions(PYPROJECT)
ROOT = pathlib.Path(__file__).parent.resolve()


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def develop(session: nox.Session) -> None:
    session.install(*nox.project.dependency_groups(PYPROJECT, "develop"))
    session.install(*nox.project.dependency_groups(PYPROJECT, "build"))
    session.install(*nox.project.dependency_groups(PYPROJECT, "test"))
    session.install(*nox.project.dependency_groups(PYPROJECT, "docs"))
    session.install(*nox.project.dependency_groups(PYPROJECT, "lint"))
    session.run("pre-commit", "install")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def lint(session: nox.Session) -> None:
    print()
    session.install(*nox.project.dependency_groups(PYPROJECT, "lint"))
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
        bash_files = ROOT.glob("**/*.sh")
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
def test(session: nox.Session) -> None:
    print("\n=== tests ===\n")
    session.install(*nox.project.dependency_groups(PYPROJECT, "test"))
    session.install(".")
    # session.run("pytest")
    session.run("pytest", "-v")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def build(session: nox.Session) -> None:
    _build(session)


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def build_sdist(session: nox.Session) -> None:
    _build(session, with_wheel=False)


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS)
def build_wheel(session: nox.Session) -> None:
    _build(session, with_sdist=False)


def _build(session: nox.Session, *, with_sdist: bool = True, with_wheel: bool = True) -> None:
    print("\n=== build ===\n")
    if not with_sdist and not with_wheel:
        print("===> nothing to build")
        return
    shutil.rmtree("dist", ignore_errors=True)
    session.install(*nox.project.dependency_groups(PYPROJECT, "build"))
    if with_sdist:
        _build_sdist(session)
    if with_wheel:
        _build_wheel(session)
    print("\n= twine check =")
    session.run("twine", "check", "dist/*")
    print("\n= check symbols =")
    if shutil.which("nm") is None:
        print("===> nm not found, skipping")
    else:
        session.run("python", "tools/check_pyext_symbol_hiding.py", "dist")


def _build_sdist(session: nox.Session) -> None:
    print("===> building sdist")
    session.run("python", "-m", "build", "--sdist")


def _build_wheel(session: nox.Session) -> None:
    print("===> building wheel")
    session.run("python", "-m", "build", "--wheel")


@nox.session(venv_backend="venv", python=SUPPORTED_PYTHON_VERSIONS[-1])
def docs(session: nox.Session) -> None:
    print("\n=== generate docs ===\n")
    mkdocs_conf = ROOT / "mkdocs.yml"
    session.install(*nox.project.dependency_groups(PYPROJECT, "docs"))
    session.run("mkdocs", "build", "--clean", "--config-file", str(mkdocs_conf))


@nox.session(venv_backend=None)
def tidy(session: nox.Session) -> None:
    print("\n=== clang-tidy ===\n")
    if shutil.which("clang-tidy") is None:
        print("===> clang-tidy not found, skipping")
        return
    commands_path = ROOT / "compile_commands.json"
    tpl_path = ROOT / "compile_commands.tpl.json"
    with tpl_path.open(encoding="utf-8") as tpl:
        template = tpl.read()
        template = template.replace("ROOT", str(ROOT))
    with commands_path.open(mode="wt", encoding="utf-8") as out:
        out.write(template)
    session.run("clang-tidy", "-header-filter=.*", "cydrogen/cyutils.c", "cydrogen/src/hydrogen.c", external=True)
