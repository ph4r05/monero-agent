import sys

from setuptools import setup
from setuptools import find_packages

version = '0.0.2'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'aiounittest',
    'monero-serialize>=0.0.6',
    'pycryptodome',

]

dev_extras = [
    'nose',
    'pep8',
    'tox',
    'aiounittest',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
]


try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
    long_description = long_description.replace("\r", '')

except(IOError, ImportError):
    import io
    with io.open('README.md', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='monero_agent',
    version=version,
    description='Monero Agent',
    long_description=long_description,
    url='https://github.com/ph4r05/monero-glue',
    author='Dusan Klinec',
    author_email='dusan.klinec@gmail.com',
    license='CLOSED',
    # license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.5',
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    },
)
