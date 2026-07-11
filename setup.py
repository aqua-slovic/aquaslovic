from setuptools import setup, find_packages

setup(
    name="aquaslovic",
    version="1.0.0",
    description="AQUA_SLOVIC - Cross-Platform Network Security Toolkit",
    author="AquaSlovic",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "colorama>=0.4.6",
        "netifaces>=0.11.0",
        "tqdm>=4.65.0",
    ],
    entry_points={
        "console_scripts": [
            "aquaslovic=aquaslovic.cli:AquaSlovicCLI",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
