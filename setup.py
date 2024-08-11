from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="veoliaAPI-CorentinGrard",
    version="0.0.1",
    author="Corentin Grard",
    author_email="corentin.grard@gmail.com",
    description="A small package to work with prime numbers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/clement-bonnet/medium-first-package",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
