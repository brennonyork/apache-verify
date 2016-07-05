#!/usr/bin/env python

# Text colors
class Color:
    PASS = '\033[32m'
    FAIL = '\033[31m'
    DEF  = '\033[39m'

class Outcome:
    PASS = {'txt': 'PASSED', 
            'color': Color.PASS}
    FAIL = {'txt': 'FAILED', 
            'color': Color.FAIL}

# Error codes
class Error:
    PREAMBLE = 1
    PROGRAM_CHECK = 2
    MKDIR = 3
    WGET = 4
    GPG = 5
    RM = 6
    OPENSSL = 7
    BINARY_FILES = 9
    DIGEST = 10
    DECOMPRESS = 11

class ApacheProject:
    def __init__(self,
                 name,
                 is_incubator=False,
                 apache_dist_url='https://dist.apache.org/repos/dist/',
                 staging_url='',
                 release_dir='',
                 comparable_digest_codes=('SHA',
                                          'MD5'),
                 necessary_files=('DISCLAIMER',
                                  'LICENSE',
                                  'NOTICE',
                                  'README.md',
                                  'CHANGELOG.md')):
        """
        Define a new Apache project.

        :param name: the shortened project name
        :param is_incubator: boolean dictating if the project is currently
        under incubation
        :param apache_dist_url: base URL for the Apache distribution where
        all projects lie
        :param staging_url: URL for the staging source code within Apache
        :param release_dir: Directory where the release is located off the
        Apache site
        :param comparable_digest_codes: allowable digest codes that the project
        natively supports to compare and check against
        :param necessary_files: set of necessary files that the project
        requires in its root directory to be valid by Apache
        """
        self.name = name
        self.is_incubator = is_incubator
        self.apache_dist_url = apache_dist_url
        if self.is_incubator:
            self.keys_url = apache_dist_url + 'release/incubator/' + \
            self.name + '/KEYS'
        else:
            self.keys_url = apache_dist_url + 'release/' + self.name + '/KEYS'
        self.comparable_digest_codes = comparable_digest_codes
        self.necessary_files = necessary_files

    def __repr__(self):
        return "ApacheProject<{}>".format(self.name)
