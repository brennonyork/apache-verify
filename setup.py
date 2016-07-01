from setuptools import setup

setup(name='apache_verify',
      version='1.0',
      description='Verification of Apache projects',
      url='https://github.com/brennonyork/apache-verify',
      author='Brennon York',
      author_email='brennon@paradiso.cc',
      license='MIT',
      packages=['apache_verify'],
      scripts=['bin/apache-verify'],
      install_requires=[
        'bs4',
        'click'],
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Build Tools'],
      zip_safe=False)
