from setuptools import setup, find_packages

setup(
    name="agentshield-sdk",
    version="1.0.0",
    description="Runtime protection and security monitoring for AI agents",
    author="Aayush",
    author_email="aayush022008@gmail.com",
    url="https://github.com/aayush022008/agentshield",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0",
        "httpx>=0.25",
        "scikit-learn>=1.3",
        "numpy>=1.24",
        "pydantic>=2.0",
        "rich>=13.0",
        "click>=8.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-asyncio>=0.21", "ruff", "mypy"],
        "langchain": ["langchain>=0.1.0"],
        "crewai": ["crewai>=0.1.0"],
        "autogen": ["pyautogen>=0.2.0"],
        "openai": ["openai>=1.0.0"],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
)
