#!/usr/bin/env python

class ApacheProject:
    def __init__(self,
                 name,
                 is_incubator=False,
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
        :param comparable_digest_codes: allowable digest codes that the project
        natively supports to compare and check against
        :param necessary_files: set of necessary files that the project
        requires in its root directory to be valid by Apache
        """
        self.name = name
        self.is_incubator = is_incubator
        self.comparable_digest_codes = comparable_digest_codes

    def __repr__(self):
        return "ApacheProject<{}>".format(self.name)
