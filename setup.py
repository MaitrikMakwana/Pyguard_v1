from setuptools import setup, find_packages

setup(
    name="pyguard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "pcapy-ng>=1.0.9",
        "psutil>=5.9.0",
        "psycopg2-binary>=2.9.5",
        "PyYAML>=6.0",
        "pandas>=1.5.0",
        "pyarrow>=10.0.0",
        "PyQt5>=5.15.7",
        "dpkt>=1.9.8",
        "netifaces>=0.11.0",
        "python-dateutil>=2.8.2",
        "sqlalchemy>=2.0.0",
        "tqdm>=4.64.1",
        "colorlog>=6.7.0",
    ],
    entry_points={
        "console_scripts": [
            "pyguard=pyguard.main:main",
        ],
    },
    author="PyGuard Team",
    author_email="info@pyguard.org",
    description="High-performance network traffic metadata capture application",
    keywords="network, traffic, capture, metadata, analysis",
    python_requires=">=3.8",
)