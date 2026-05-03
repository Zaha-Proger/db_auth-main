from setuptools import setup

setup(
    name="pygost",
    version="6.0",
    description="Pure Python GOST cryptographic functions library",
    long_description=open("README", "rb").read().decode("utf-8"),
    author="Sergey Matveev",
    author_email="stargrave@stargrave.org",
    url="http://www.pygost.cypherpunks.su/",
    license="GPLv3",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=["pygost", "pygost.asn1schemas"],
    data_files=(
        ("", ("AUTHORS", "COPYING", "FAQ", "INSTALL", "NEWS", "README", "THANKS")),
    ),
    tests_require=["pyderasn~=9.3"],
)
