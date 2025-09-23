from setuptools import setup, find_packages

setup(
    name="nexus-signal-engine",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "rapidfuzz",
        "filelock",
        "nltk",
        "scikit-learn",
        "tenacity"
    ],
    author="Jonathan Harrison",
    author_email="",
    description="A real-world, agent-driven, adversarially resilient AI signal analysis and memory engine",
    long_description="A real-world, agent-driven, adversarially resilient AI signal analysis and memory engine.",
    long_description_content_type="text/plain",
    url="https://github.com/Raiff1982/Nexus-signal-engine",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)