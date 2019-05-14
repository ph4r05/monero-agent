import os
import glob
import subprocess
import sys
import logging

from setuptools import setup, Command, find_packages
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop
from distutils.errors import DistutilsError


logger = logging.getLogger(__name__)


version = "2.0.6"

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    "monero-serialize>=3.0.1",
    "pycryptodome",
    "py-cryptonight>=0.1.2",
    "chacha20poly1305",
]

dev_extras = [
    "nose",
    "pep8",
    "tox",
    "aiounittest",
    "requests",
    "pympler",
    "pypandoc",
    "pandoc",
    "pip",
    "pycparser",
    "ctypeslib2",
    "cryptography",  # chacha20poly1305
    "protobuf==3.4.0",
]

poc_extras = [
    "ecdsa",
    "asyncio",
    "requests",
    "cmd2>=0.6.9",
    "shellescape",
    "coloredlogs",
    "blessed>=1.14.1",
    "flask>=0.12",
    "flask-socketio",
    "eventlet",
    "gevent",
    "sarge>=0.1.5",
]

# trezor-crypto backend, secure and fast
tcry_extras = [
    "py_trezor_crypto_ph4==0.1.1",
]

docs_extras = [
    "Sphinx>=1.0",  # autodoc_member_order = 'bysource', autodoc_default_flags
    "sphinx_rtd_theme",
    "sphinxcontrib-programoutput",
]

# trezor dependencies, trezorlib
trezorlib_git = 'https://github.com/trezor/python-trezor.git'
trezorlib_git = 'https://github.com/ph4r05/python-trezor.git'
trezorlib_commit = '2377af23f70c7c4d53921324681ff7884a0308ef'
trezor_extras = [
    "trezor",
]


CWD = os.path.dirname(os.path.realpath(__file__))
TREZOR_COMMON = os.path.join(CWD, 'monero_vendor', 'trezor-common')


class InstallTrezorlib(Command):
    description = 'installs trezorlib with the exact needed version'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import shutil
        import tempfile
        import subprocess
        tmpd = tempfile.mkdtemp()

        try:
            subprocess.call(["git", "clone", trezorlib_git, "."], cwd=tmpd)
            subprocess.call(["git", "checkout", trezorlib_commit], cwd=tmpd)
            subprocess.call(["git", "submodule", "init"], cwd=tmpd)
            subprocess.call(["git", "submodule", "update", "--recursive"], cwd=tmpd)

            # Not nice, but due to virtualenv we dont know which pip is being used
            try:
                from pip._internal import main as pip_main
                pip_main(["install", "-U", tmpd])

            except Exception as e:
                logger.warning('Programatical pip installation failed: %s' % e)

                pip_path = os.getenv('PIP_PATH', None)
                pip = os.path.join(pip_path, 'pip') if pip_path else 'pip'
                subprocess.call([pip, "install", "-U", tmpd])

        except Exception as e:
            msg = 'Error installing "trezor" package. Try the manual way: ' \
                  'git clone %s /tmp/trezorlib && cd /tmp/trezorlib && git checkout %s && ' \
                  'git submodule init && git submodule update --recursive && ' \
                  'cd - && pip install -U /tmp/trezorlib' % (trezorlib_git, trezorlib_commit)
            raise DistutilsError(msg) from e
        finally:
            shutil.rmtree(tmpd)


class PrebuildCommand(Command):
    description = 'update vendored files (coins.json, protobuf messages)'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # check for existence of the submodule directory
        common_defs = os.path.join(TREZOR_COMMON, 'defs')
        if not os.path.exists(common_defs):
            raise DistutilsError('trezor-common submodule seems to be missing.\n' +
                                 'Use "git submodule update --init" to retrieve it.')

        # regenerate messages
        try:
            proto_srcs = glob.glob(os.path.join(TREZOR_COMMON, "protob", "*.proto"))
            subprocess.check_call([
                sys.executable,
                os.path.join(TREZOR_COMMON, "protob", "pb2py"),
                "-o", os.path.join(CWD, "monero_glue", "messages"),
                "-P", "..protobuf",
            ] + proto_srcs)
        except Exception as e:
            raise DistutilsError("Generating protobuf failed. Make sure you have 'protoc' in your PATH.") from e


def _patch_prebuild(cls):
    """Patch a setuptools command to depend on `prebuild`"""
    orig_run = cls.run

    def new_run(self):
        self.run_command('prebuild')
        orig_run(self)

    cls.run = new_run


_patch_prebuild(build_py)
_patch_prebuild(develop)


try:
    import pypandoc

    long_description = pypandoc.convert("README.md", "rst")
    long_description = long_description.replace("\r", "")

except (IOError, ImportError):
    import io

    with io.open("README.md", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="monero_agent",
    version=version,
    description="Monero Agent",
    long_description=long_description,
    url="https://github.com/ph4r05/monero-agent",
    author="Dusan Klinec",
    author_email="dusan.klinec@gmail.com",
    license='MIT',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Security",
    ],
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.5",
    install_requires=install_requires,
    extras_require={
        "dev": dev_extras,
        "poc": poc_extras,
        "docs": docs_extras,
        "tcry": tcry_extras,
        "trezor": trezor_extras,
    },
    cmdclass={
        'prebuild': PrebuildCommand,
        'install_trezorlib': InstallTrezorlib,
    },
    entry_points={
        'console_scripts': [
            'monero-seed = monero_poc.seed:main',
            'monero-agent = monero_poc.agent:main',
            'monero-trezor-poc = monero_poc.trezor:main',
            'monero-trezor-init = monero_poc.trezor_init:main',
            'monero-trezor-log = monero_poc.log_aux:main',
            'monero-test-gen = monero_poc.tools.test_gen:main',
        ],
    }

)
