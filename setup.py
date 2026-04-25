"""HomeShield — Home Network Exposure Measurement Tool."""

from setuptools import setup, find_packages

setup(
    name="homeshield",
    version="1.0.0",
    description="Defensive home/SOHO network exposure measurement CLI tool",
    author="Abbas Najmi",
    url="https://github.com/Aanajmi/HOME-SHIELD",
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        "jinja2>=3.0",
    ],
    entry_points={
        "console_scripts": [
            "homeshield=homeshield.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
    ],
)
