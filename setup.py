from setuptools import setup, find_packages


requires = ['aiohttp',
            'ticket_auth',]


tests_require = ['aiohttp_session']


setup(
    name="aiohttp_auth",
    version='0.1.1',
    description='Authorization and authentication middleware plugin for aiohttp.',
    long_description=open('README.rst').read(),
    install_requires=requires,
    packages=find_packages(exclude=['tests*']),
    author='Gnarly Chicken',
    author_email='gnarlychicken@gmx.com',
    test_suite='tests',
    tests_require=tests_require,
    url='https://github.com/gnarlychicken/aiohttp_auth',
    license='MIT',
    classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Topic :: Internet :: WWW/HTTP :: Session',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3 :: Only',
            'Programming Language :: Python :: 3.5',
        ],)
