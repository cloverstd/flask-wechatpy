#!/usr/bin/env python
# encoding: utf-8

from setuptools import setup

setup(
    name='Flask-wechatpy',
    version='0.1.0',
    url='https://github.com/cloverstd/flask-wechatpy',
    license='MIT',
    author='cloverstd',
    author_email='cloverstd@gmail.com',
    description='wechatpy for flask extension',
    long_description=__doc__,
    py_modules=['flask_wechatpy'],
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
