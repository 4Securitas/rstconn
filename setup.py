import re

from glob import glob
from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

_pkg_name = 'rstconn'

with open(f'{_pkg_name}/__init__.py', 'r') as fd:
    VERSION = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name=_pkg_name,
    version=VERSION,
    description="A TCPKill utility written in python and scapy",
    long_description=readme(),
    long_description_content_type='text/markdown',
    classifiers=['Development Status :: 5 - Production/Stable',
                 'License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)',
                 'Programming Language :: Python :: 3'],
    url='https://github.com/4Securitas/rstconn',
    author='Giuseppe De Marco',
    author_email='demarcog83@gmail.com',
    license='License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)',
    scripts=[f'{_pkg_name}/bin/{_pkg_name}'],
    packages=[f"{_pkg_name}"],
    package_dir={f"{_pkg_name}": f"{_pkg_name}"},
    package_data={f"{_pkg_name}": [
            i.replace(f'{_pkg_name}/', '')
            for i in glob(f'{_pkg_name}/**', recursive=True)
        ]
    },
    install_requires=[
        'scapy>=2.4.5',
        'ifaddr>=0.1.7'
    ],
)
