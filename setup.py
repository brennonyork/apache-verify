from setuptools import setup, find_packages

setup(name='apache_verify',
      version='1.0',
      description='Verification of Apache projects',
      url='https://github.com/brennonyork/apache-verify',
      author='Brennon York',
      author_email='brennon@paradiso.cc',
      license='MIT',
      #packages=['apache_verify'],
      packages=find_packages(),
      #scripts=['bin/apache-verify'],
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
      entry_points='''
          [console_scripts]
          apache_verify=apache_verify.src.verify:main
      ''',
      zip_safe=False)
