from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="veoliAPI",
    version="0.0.3",
    author="Corentin Grard",
    author_email="corentin.grard@gmail.com",
    description="To get the monthly water consumption from the Veolia API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CorentinGrard/VeoliAPI",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "aiohttp",
    ],
    python_requires='>=3.6',
)
