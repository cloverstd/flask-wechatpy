#!/usr/bin/env python
# encoding: utf-8

from setuptools import setup, find_packages

setup(
    name='Flask-wechatpy',
    version='0.1.2',
    url='https://github.com/cloverstd/flask-wechatpy',
    license='MIT',
    author='cloverstd',
    author_email='cloverstd@gmail.com',
    description='wechatpy for flask extension',
    long_description=__doc__,
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'wechatpy>=1.2.12',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
