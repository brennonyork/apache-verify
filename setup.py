from setuptools import setup

setup(name='apache_verify',
      version='1.0',
      description='Verification of Apache projects',
      url='https://github.com/brennonyork/apache-verify/',
      author='Brennon York',
      author_email='brennon@paradiso.cc',
      license='MIT',
      packages=['apache_verify'],
      scripts=['bin/apache-verify'],
      zip_safe=False)
