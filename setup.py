from setuptools import setup, find_packages

setup(
    name='NashOTXCLI',
    version='0.1.0',
    author='Moahmmed althaf',
    author_email='althafnash14@gmail.com',
    description='OTX API based CLI',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Althafnash/OTXCLI.git',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=[
        # Add dependencies here
    ],
)
