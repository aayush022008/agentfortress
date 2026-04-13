from setuptools import setup, find_packages

setup(
    name="agentshield-monitor",
    version="1.0.0",
    description="CLI for AgentShield — AI Agent Security Platform",
    author="Aayush",
    author_email="aayush022008@gmail.com",
    url="https://github.com/aayush022008/agentshield",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "httpx>=0.25",
    ],
    entry_points={"console_scripts": ["agentshield=agentshield_cli.main:main"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
