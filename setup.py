import setuptools

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()


__version__ = "0.0.0"

REPO_NAME = "packet-parsing"
AUTHOR_USER_NAME = "mpaul7"
SRC_REPO = "parser"
AUTHOR_EMAIL = "mpaul7@gmail.com"


setuptools.setup(
    name=SRC_REPO,
    version=__version__,
    author="Manjinder",
    author_email="mpaul7@gmail.com",
    description="Packet Parsing",
    long_description=long_description,
    long_description_content="text/markdown",
    url=f"https://github.com/{AUTHOR_USER_NAME}/{REPO_NAME}",
    project_urls={
        "Bug Tracker": f"https://github.com/{AUTHOR_USER_NAME}/{REPO_NAME}/issues",
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src")
)