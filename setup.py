from setuptools import setup


requires = ['aiohttp',
            'ticket_auth',]

setup(
    name="aiohttp_auth",
    version='0.1.0',
    description='Authorization and authentication middleware plugin for aiohttp.',
    long_description=open('README.rst').read(),
    install_requires=requires,
    packages=['aiohttp_auth'],
    author='Gnarly Chicken',
    author_email='gnarlychicken@gmx.com',
    test_suite='tests',
    url='https://github.com/gnarlychicken/aiohttp_auth',
    license='MIT',
    classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Topic :: Internet :: WWW/HTTP :: Session',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3 :: Only',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
        ],)
