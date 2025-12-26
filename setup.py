from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="1.0.0",
    description="Minimalist Cryptographic Provider",
    author="AllowDead",
    packages=find_packages(),
    install_requires=[
        "pycryptodome>=3.20.0",
        "pyopenssl>=3.2.1",
    ],
    entry_points={
        "console_scripts": [
            "cryptocore=cryptocore.cli_parser:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)