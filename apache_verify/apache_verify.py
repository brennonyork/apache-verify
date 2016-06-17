#!/usr/bin/env python

##
# desc: This program will attempt to automatically verify any apache project
#       release candidate (RC) that it understands. Verification info and steps
#       can be found on the Apache website [1].
#       http://www.apache.org/info/verification.html
#
# arg1: project to pull, build, and test from the supported list
# arg2: version of the project to build (e.g. 5.4.0)
# arg3: release candidate to use (e.g. RC-1)
#
# ret:  report written to STDOUT
##

import os
import re
import sys
import subprocess

##
# Global variables
##

CWD = os.getcwd()

# the left pad margin before printing PASS or FAIL text
L_PAD = 40

# Text colors
class Colors:
    PASS = '\033[32m'
    FAIL = '\033[31m'
    DEF  = '\033[39m'

class Outcome:
    PASS = {'txt': 'PASSED', 
            'color': Colors.PASS}
    FAIL = {'txt': 'FAILED', 
            'color': Colors.FAIL}

class Error:
    BINARY_FILES = 9
    DIGEST = 10
    DECOMPRESS = 11

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

apex-malhar = ApacheProject('apex')
                            

# distribution URL for all Apache projects
apache_dist_url = "https://dist.apache.org/repos/dist/"

# Staging directory to download all files to (relative to calling directory)
# note - this is a local directory
STAGING_DIR="staging"

# URL for the staging source code within Apache
STAGING_URL=""
# URL for the KEYS file to verify and import correct signatures
KEYS_URL=""
# Directory where the release is located off the Apache site
RELEASE_DIR=""
# Version of the project to download and test
PROJ_VERSION=""
# Release candidate to test against
RC=""


def print_error_and_exit(err_msg, exit_code):
    err_prefix = Colors.FAIL + 'ERROR:' + Colors.DEF

    print err_prefix, err_msg
    sys.exit(exit_code)


def run_command(exit_code, *popen_args, **kwargs):
    try:
        if 'return_code' in kwargs and kwargs['return_code'] == True:
            ret = subprocess.check_call(popen_args, kwargs)
        else:
            ret = subprocess.check_output(popen_args, kwargs)
    except subprocess.CalledProcessError:
        print_error_and_exit('running command ' + ' '.join(popen_args),
                             exit_code)
    return ret


def run_command_into_devnull(exit_code, *popen_args, **kwargs):
    with open(os.devnull, 'w') as devnull:
        kwargs['stderr'] = subprocess.stdout
        kwargs['stdout'] = devnull

        ret = run_command(exit_code, popen_args, kwargs)
    return ret


def build_outcome_stmt(outcome, ltxt='', rtxt=None):
    if not isinstance(outcome, Outcome):
        print "error code: TODO HERE"
        sys.exit(1)

    outcome_txt = '{:<{}s}' + outcome['color'] + outcome['txt']
    
    if rtxt:
        outcome_txt += '; ' + rtxt + Colors.DEF
    else:
        outcome_txt += Colors.DEF

    return outcome_txt.format(ltxt, L_PAD)


# arg1: program to determine if present on the system as a string
# ret:  if the program is present nothing else print a message asking to
#       install the program and exit
def check_for_command(prog_name):
    run_command(1, ['command', '-v', prog_name]):


def import_keys(keys_url):
    wget_cmd = ['wget', '-nc', '-np', '-nd', '--quiet', keys_url]
    gpg_cmd  = ['gpg', '--import', 'KEYS']

    run_command(wget_cmd)
    run_command_into_devnull(gpg_cmd)

def download_sourcecode(staging_url):
    wget_cmd = ['wget', '-r', '-nc', '-np', '-nd', '--reject', 'html/txt',
                '--quiet', staging_url]

    run_command(wget_cmd)

    # remove any robots file if found
    run_command(['rm', '-f', 'robots.txt'])

# arg1: filename with a corresponding .asc file to verify using gpg
# ret:  text of the gpg verification command
def verify_asc(basefile):
    gpg_output_filename = 'gpg-verify-output'

    with os.fdopen(os.open(gpg_output_filename, 
                           os.O_RDWR|os.O_CREAT), "w+") as gpg_output_file:
        gpg_cmd = ['gpg', '--verify',
                   '--status-fd=' + gpg_output_file.fileno(),
                   basefile + '.asc', basefile]

        print "Verifying Sig:", os.path.basename(basefile)
        run_command_into_devnull(gpg_cmd)

        gpg_output = gpg_output_file.read()
        matches = re.findall(r'GOODSIG|VALIDSIG', gpg_output)

        if "GOODSIG" in matches and "VALIDSIG" in matches:
            print build_outcome_stmt(Outcome.PASS, rtxt='GOODSIG, VALIDSIG')
        else:
            print build_outcome_stmt(Outcome.FAIL, rtxt='BADSIG')
            print gpg_output

    run_command(['rm', '-f', gpg_output_filename])

# arg1: digest type (either "SHA" or "MD5")
# arg2: file to compare with extension (e.g. "tar.gz" or "zip")
# ret:  text stating whether the digest comparison was a match or not 
def compare_digest(digest_type, filename):
    digest_codes = {'SHA': {'openssl_code': '-sha512',
                            'file_ext': 'sha'}
                    'MD5': {'openssl_code': '-md5',
                            'file_ext': 'md5'}}

    if not digest_type in digest_codes:
        print_error_and_exit("only 'SHA' and 'MD5' digests available",
                             Error.DIGEST)

    openssl_cmd = ['openssl', 'dgst', 
                   digest_codes[digest_type]['openssl_code'],
                   filename]

    calced_digest = run_command(openssl_cmd).split(' ')[1]
    
    with open(filename + digest_codes[digest_type]['file_ext'],
              'r') as given_digest_file:
        given_digest = given_digest_file.read().strip().split(' ')[0]

    if calced_digest == given_digest:
        print build_outcome_stmt(Outcome.PASS, ltxt=filename + ':',
                                 rtxt='Match')
    else:
        print build_outcome_stmt(Outcome.FAIL, ltxt=filename + ':',
                                 rtxt='Mismatch')

# arg1: filename of the tarball or zip file
def compare_all_digests(proj, abs_filename):
    print "Checking digest:", os.path.basename(abs_filename)
    
    for digest in proj.comparable_digest_codes:
        compare_digest(digest, abs_filename)

# arg1: name of file to find within the project directory
# ret:  text stating whether the file was found or not
def check_for_files(proj):
    output = run_command(['ls'])
    
    for file in proj.necessary_files:
        if not re.findall(file, output):
            print build_outcome_stmt(Outcome.FAIL, ltxt=file + ':',
                                     rtxt='Not found')
        else:
            print build_outcome_stmt(Outcome.PASS, ltxt=file + ':',
                                     rtxt='Found')


# arg1: the compressed source ball (either tar.gz or zip)
def expand_bundle(sourceball):
    decompress_codes = {'gz': ['tar', '-xzf'],
                        'zip': ['unzip', '-oqq']}

    ext = os.path.splitext(sourceball)[1]

    if not ext in decompress_codes:
        print_error_and_exit("cannot expand file type '" + ext + "'",
                             Error.DECOMPRESS)

    decompress_cmd = decompress_codes[ext]
    decompress_cmd.append(sourceball)

    run_command(decompress_cmd)

# ret: text stating whether the RAT checks passed or not
def check_rat():
    mvn_cmd = ['mvn', 'apache-rat:check']

    if run_command_into_devnull(mvn_cmd, return_code=True) == 0:
        print build_outcome_stmt(Outcome.PASS, ltxt='RAT Check:')
    else:
        print build_outcome_stmt(Outcome.FAIL, ltxt='RAT Check:')


def check_for_binary_files():
    find_cmd = ['find', '.', '-type', 'f']
    xargs_cmd = ['xargs', '-I{}', 'file', '{}']
    egrep_cmd = ['egrep', '-v', 'empty|text$|^\./\.git']

    find_proc = subprocess.Popen(find_cmd, stdout=subprocess.PIPE)
    xargs_proc = subprocess.Popen(xargs_cmd,
                                  stdin=find_proc.stdout,
                                  stdout=subprocess.PIPE)
    egrep_output = run_command(Error.BINARY_FILES,
                               egrep_cmd,
                               stdin=xargs_proc.stdout)
    if egrep_output:
        print build_outcome_stmt(Outcome.FAIL, ltxt='Binary File Check')

        for file in egrep_output.split('\n'):
            print '{:<{}s}'.format(file, L_PAD)
    else:
        print build_outcome_stmt(Outcome.PASS, ltxt='Binary File Check')


def compile_source():
    mvn_cmd = ['mvn', 'clean', 'install', '-DskipTests']

    if run_command_into_devnull(mvn_cmd, return_code=True) == 0:
        print build_outcome_stmt(Outcome.PASS, ltxt='RAT Check:')
    else:
        print build_outcome_stmt(Outcome.FAIL, ltxt='RAT Check:')


def execute_tests():
    mvn_cmd = ['mvn', 'install']

    if run_command_into_devnull(mvn_cmd, return_code=True) == 0:
        print build_outcome_stmt(Outcome.PASS, ltxt='RAT Check:')
    else:
        print build_outcome_stmt(Outcome.FAIL, ltxt='RAT Check:')


def test_source(filename):
    print "Expanding:", os.path.basename(filename)

    expand_bundle(filename)

"""
test_source() {
    printf "\nExpanding: $(basename $1)\n"
    expand_bundle "$1"

    local expanded_dir="$(find . -type d -d 1)"
    cd "$expanded_dir"

    # 3. Check for existence of DISCLAIMER, LICENSE, NOTICE, README.md and 
    #    CHANGELOG.md

    check_for_all_files

    # 4. Run RAT checks

    check_rat

    # 5. Check for any binary files

    check_for_binary_files

    # 6. Check compilation

    compile_source

    # 7. Execute tests

    execute_tests

    cd ..
    rm -rf "${expanded_dir}" 
}
"""


def main(argv, argc):
    if argc < 2:
        print "Usage: ./apache-verify <project-name> <version> [ <release> ]"
        # TODO: exit

    project_name = argv[1]

# check for a valid apache project to verify
if [[ ! "$1" || ! "$2" || ! "$3" ]]; then
    printf "${FAIL_T_C}USAGE:${DEF_T_C} "
    printf "$ ./apache-verify-release <project-name> <version> "
    printf "<release-candidate>\n"
    exit 1
fi

# set the project version and release candidate variables
PROJ_VERSION="$2"

# if we are checking a release candidate (and it was supplied on the command
# line) then check for it here
if [[ -n "$3" ]]; then
    RC="$3"
    RC_SUFFIX="-$3"
else
    RC=""
    RC_SUFFIX=""
fi

# ensure the project is one that is supported
case "$1" in
    "apex-core")
	IS_INCUBATOR=""
	RELEASE_DIR="apache-apex-core-${PROJ_VERSION}${RC_SUFFIX}/"
	STAGING_URL="${apache_dist_url}dev/incubator/apex/${RELEASE_DIR}"
	KEYS_URL="${apache_dist_url}release/incubator/apex/KEYS"
	;;
    "apex-malhar")
	IS_INCUBATOR=""
	APACHE_PROJ_NAME="apex"
	RELEASE_DIR="apache-apex-malhar-${PROJ_VERSION}${RC_SUFFIX}/"
	STAGING_URL="${apache_dist_url}dev/incubator/apex/${RELEASE_DIR}"
	KEYS_URL="${apache_dist_url}release/incubator/apex/KEYS"
	;;
    *)
	printf "Valid projects to verify:\n"
	printf "\tapex-core\n"
	printf "\tapex-malhar\n"
	exit 1
	;;
esac

# arg1: apache project name
# arg2: boolean string to determine if the project is an incubator or not
# arg3: release directory name
build_staging_url() {
    if [[ -n "$2" ]]; then
	echo "${apache_dist_url}dev/incubator/$1/$3"
    else
	echo "${apache_dist_url}dev/incubator/$1/$3"
    fi
}

STAGING_URL="$(build_staging_url )"

# 0. Ensure machine has the correct prerequisite programs, files, etc.

check_for_command "gpg"
check_for_command "wget"
check_for_command "openssl"
check_for_command "mvn"

# download all necessary files into the staging directory
if [[ ! -d "${STAGING_DIR}" ]]; then
    mkdir -p "${STAGING_DIR}"
fi

cd "${STAGING_DIR}"

import_keys

download_sourcecode

TGZ_FILENAME="$(find . -name '*.tar.gz')"
ZIP_FILENAME="$(find . -name '*.zip')"

# 1. Validate signature

verify_asc "${TGZ_FILENAME}"
verify_asc "${ZIP_FILENAME}"

# 2. Check the signature

compare_all_digests "${TGZ_FILENAME}"
compare_all_digests "${ZIP_FILENAME}"

test_source "${TGZ_FILENAME}"
test_source "${ZIP_FILENAME}"

# 7. Cleanup

cd "${CWD}"
rm -rf "${STAGING_DIR}"

if __name__ == "__main__":
    try:
        main(sys.argv, len(sys.argv))
    except KeyboardInterrupt:
        print "noe"
