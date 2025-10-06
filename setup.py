from setuptools import setup, find_packages

setup(
    name="AI-related dataset scrapy",
    version="0.1.0",
    description="Scraping data for AI security research",
    author="Yongxi Sha",
    author_email="yongxi.sha@usu.edu",
    packages=find_packages(),
    install_requires=[
    ],
    entry_points={
        "console_scripts": [
            "scraping = scraping.main:main",  # from scraping/main.py
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)


