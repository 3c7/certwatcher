from setuptools import setup, find_packages

with open('README.md') as f:
    long_description = f.read()

setup(
    name='certwatcher',
    version='0.2.0',
    description='Watching certificate registrations through certstream and search for suspicious behavior',
    long_description=long_description,
    url='https://nope',
    author='Nils Kuhnert',
    license='MIT',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Environment :: Console'
    ],
    keywords='analysis phishing certificates certstream transparency apt advanced persistent threats',
    packages=find_packages(),
    install_requires=[
        'Click',
        'termcolor',
        'yara-python',
        'certstream',
        'PyYAML'
    ],
    entry_points={
        'console_scripts': [
            'certwatcher=certwatcher.cli:cli'
        ]
    }
)
