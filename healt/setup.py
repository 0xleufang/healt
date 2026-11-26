from pathlib import Path
from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parent
README = ROOT / "README.md"
REQ = ROOT / "requirements.txt"

install_requires = ["psutil", "rich"]
if REQ.exists():
    extra = [
        line.strip()
        for line in REQ.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    for pkg in extra:
        if pkg not in install_requires:
            install_requires.append(pkg)

setup(
    name="healt",
    version="0.1.0",
    description="Signature scan and sandbox guard before placing external repositories",
    long_description=README.read_text(encoding="utf-8") if README.exists() else "",
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    package_data={"healt_data": ["../rules/*.json"]},
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "healt=healt_data.cli:main",
        ],
    },
)
