"""setup module."""

import re
from distutils.core import setup
from pathlib import Path

from setuptools import find_packages

name = "mse_lib_sgx"

version = re.search(
    r"""(?x)
    __version__
    \s=\s
    \"
    (?P<number>.*)
    \"
    """,
    Path(f"src/{name}/__init__.py").read_text(),
)

setup(
    name=name,
    version=version["number"],
    url="https://cosmian.com",
    license="MIT",
    author="Cosmian Tech",
    author_email="tech@cosmian.com",
    description="Library for Cosmian MSE to bootstrap Flask application",
    packages=find_packages("src"),
    package_dir={"": "src"},
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    zip_safe=False,
    install_requires=[
        "cryptography>=39.0.0,<40.0.0",
        "intel-sgx-ra>=1.0,<1.1",
        "hypercorn[uvloop]>=0.14.3,<0.15.0",
        "h2>=4.1.0,<4.2.0",
        "mse-lib-crypto>=1.1,<1.2",
    ],
    entry_points={
        "console_scripts": [
            "mse-bootstrap = mse_lib_sgx.cli.boostrap:run",
            "mse-bootstrap-debug = mse_lib_sgx.cli.debug:run",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    setup_requires=["wheel"],
    tests_require=["pytest>=7.1.3,<7.2.0"],
    include_package_data=True,
)
