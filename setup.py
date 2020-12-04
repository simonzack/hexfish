from setuptools import setup

setup(
    name='hexfish',
    version='1.0',
    description='Python 3 fish encryption plugin for hexchat',
    url='https://github.com/simonzack/hexfish',
    author='simonzack',
    author_email='simonzack@gmail.com',
    license='MIT',
    packages=['hexfish'],
    install_requires=[
        'pycryptodome==3.9.9',
        'tabulate==0.8.7',
    ],
    zip_safe=False
)
