from setuptools import setup, find_packages

setup(
    name="fancyHelpers",  # Name of your package
    version="0.1",  # Version of the package
    packages=find_packages(
        where="modules"
    ),  # This will find all subpackages inside the modules folder
    package_dir={
        "": "modules"
    },  # This tells setuptools where to find the modules directory
    install_requires=[  # Add any external dependencies here if needed
        "pandas",
        "seaborn",
        "matplotlib",
    ],
)
