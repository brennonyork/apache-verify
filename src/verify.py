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
import click
import hashlib
import urllib2
import subprocess

from base import Color, Error, Outcome
from bs4 import BeautifulSoup
from projects import *

##
# Global variables
##

CWD = os.getcwd()

# the left pad margin before printing PASS or FAIL text
L_PAD = 40


def print_error_and_exit(err_msg, exit_code):
    err_prefix = Color.FAIL + 'ERROR:' + Color.DEF

    print err_prefix, err_msg
    sys.exit(exit_code)


def run_command(exit_code, popen_args, **kwargs):
    try:
        if 'return_code' in kwargs and kwargs['return_code'] == True:
            kwargs.pop('return_code', None)
            ret = subprocess.check_call(popen_args, **kwargs)
        elif 'stdout' in kwargs:
            # design note: this is necessary to write stdout into devnull as
            # subprocess.check_output does not allow it for suppressing output.
            # this also creates the issue that errors here aren't raises
            # as proper exceptions. this is used in the run_command_into_devnull
            # function.
            # TODO: is there a better way?
            ret = subprocess.call(popen_args, **kwargs)
        else:
            ret = subprocess.check_output(popen_args, **kwargs)
    except subprocess.CalledProcessError:
        print_error_and_exit('running \'' + ' '.join(popen_args) + '\'',
                             exit_code)
    return ret


def run_command_into_devnull(exit_code, popen_args, **kwargs):
    with open(os.devnull, 'w') as devnull:
        kwargs['stderr'] = subprocess.STDOUT
        kwargs['stdout'] = devnull

        ret = run_command(exit_code, popen_args, **kwargs)
    return ret


def build_outcome_stmt(outcome, ltxt='', rtxt=None):
    '''
    Accepts an Outcome object and optional left and right text to augment the
    outcome statement.
    '''
    outcome_txt = '{:<{}s}' + outcome['color'] + outcome['txt']
    
    if rtxt:
        outcome_txt += '; ' + rtxt + Color.DEF
    else:
        outcome_txt += Color.DEF

    return outcome_txt.format(ltxt, L_PAD)


# arg1: program to determine if present on the system as a string
# ret:  if the program is present nothing else print a message asking to
#       install the program and exit
def check_for_programs(prog_names):
    '''
    determine if the set of programs provided are present on the system

    :param prog_names: set of programs to check for existence
    '''
    for prog_name in prog_names:
        run_command(Error.PROGRAM_CHECK, ['command', '-v', prog_name])


def import_keys(keys_url):
    wget_cmd = ['wget', '-nc', '-np', '-nd', '--quiet', keys_url]
    gpg_cmd  = ['gpg', '--import', 'KEYS']

    run_command(Error.WGET, wget_cmd)
    run_command_into_devnull(Error.GPG, gpg_cmd, return_code=True)


def download_sourcecode(url):
    wget_cmd = ['wget', '-r', '-nc', '-np', '-nd', '--reject', 'html/txt',
                '--quiet', url]

    run_command(Error.WGET, wget_cmd)

    # remove any robots file if found
    run_command(Error.RM, ['rm', '-f', 'robots.txt'])


# arg1: filename with a corresponding .asc file to verify using gpg
# ret:  text of the gpg verification command
def verify_asc(basefile):
    gpg_output_filename = 'gpg-verify-output'
    valid_sig_re = re.compile(r'GOODSIG|VALIDSIG')
    signer_re = re.compile(r'GOODSIG [0-9A-F]{16} .*')

    with open(gpg_output_filename, 'w+') as gpg_output_file:
        gpg_cmd = ['gpg', '--verify',
                   '--status-fd=' + str(gpg_output_file.fileno()),
                   basefile + '.asc', basefile]

        run_command_into_devnull(Error.GPG, gpg_cmd)

    # design note: we must close the file before reading as it seems the only
    # way python will allow the file contents to be read. even working with a
    # `.flush()` will not write out the contents and any form of reading without
    # closing the file results in nothing read into the `gpg_output` variable.
    with open(gpg_output_filename, 'r') as gpg_output_file:
        gpg_output = gpg_output_file.read()

        matches = valid_sig_re.findall(gpg_output)

        signer = ' '.join(signer_re.findall(gpg_output)[0].split()[-3:])

        if 'GOODSIG' in matches and 'VALIDSIG' in matches:
            print build_outcome_stmt(Outcome.PASS, ltxt='Verifying Signature:',
                                     rtxt='GOODSIG from '+signer)
        else:
            print build_outcome_stmt(Outcome.FAIL, ltxt='Verifying Signature:',
                                     rtxt='BADSIG')
            print gpg_output

    run_command(Error.RM, ['rm', '-f', gpg_output_filename])


# arg1: digest type (either "SHA" or "MD5")
# arg2: file to compare with extension (e.g. "tar.gz" or "zip")
# ret:  text stating whether the digest comparison was a match or not 
def compare_digests(filename, dgst_cmds):
    for dgst, dgst_cmd in dgst_cmds.iteritems():
        dgst_cmd = dgst_cmd.strip().split() + [filename]

        calced_digest = run_command(Error.DIGEST, dgst_cmd)

        # TODO: move this to a urllib2.urlopen(*).read() call
        with open(filename + '.' + dgst, 'r') as given_digest_file:
            given_digest = given_digest_file.read()

        if calced_digest == given_digest:
            print build_outcome_stmt(Outcome.PASS, ltxt='Validating Digest('+dgst+'):',
                                     rtxt='Match')
        else:
            print build_outcome_stmt(Outcome.FAIL, ltxt='Validating Digest('+dgst+'):',
                                     rtxt='Mismatch')


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


def compile_source(compile_cmd_str):
    compile_cmd = compile_cmd_str.split()

    if run_command_into_devnull(compile_cmd, return_code=True) == 0:
        print build_outcome_stmt(Outcome.PASS, ltxt='Compile Source:')
    else:
        print build_outcome_stmt(Outcome.FAIL, ltxt='Compile Source:')


def execute_tests(test_cmd_str):
    test_cmd = test_cmd_str.split()

    if run_command_into_devnull(test_cmd, return_code=True) == 0:
        print build_outcome_stmt(Outcome.PASS, ltxt='Execute Tests:')
    else:
        print build_outcome_stmt(Outcome.FAIL, ltxt='Execute Tests:')


def test_source(filename):
    print "Expanding:", os.path.basename(filename)

    expand_bundle(filename)

    expanded_dir = run_command(['find', '.', '-type', 'd', '-d', '1'])

    #cd 'expanded_dir'

    # Check for existence of necessary files

    #check_for_files(<proj>)

    # Run RAT tests

    #check_rat()

    # Check for any binary files

    #check_for_binary_files()

    # Check compilation

    #compile_source()

    # Execute tests

    #execute_tests()

    #cd ..
    #rm -rf 'expanded_dir'


@click.command()
@click.option('--keys-url',
              default=False,
              nargs=1,
              help='URL to the KEYS file for verification')
@click.option('--md5-digest-cmd',
              default='openssl dgst -md5')
@click.option('--sha512-digest-cmd',
              default='openssl dgst -sha512')
@click.option('--rat-cmd',
              default='mvn apache-rat:check',
              help='command to properly execute a RAT check')
@click.option('--compile-cmd',
              default='mvn clean install -DskipTests',
              help='command to properly execute source code compilation')
@click.option('--test-cmd',
              default='mvn install',
              help='command to properly execute source code tests')
@click.option('--staging-dir',
              default='./staging-local',
              help='local directory to perform testing')
@click.option('--select-package',
              is_flag=True)
@click.argument('release-url')
def main(release_url,
         keys_url,
         md5_digest_cmd,
         sha512_digest_cmd,
         rat_cmd,
         compile_cmd,
         test_cmd,
         staging_dir,
         select_package):
    necessary_programs = set(['gpg', 'wget'])

    # allowable file extensions that are supported. they sit as a regex to
    # ensure we check the end of the file path of an unknown size. e.g.
    # 'zip' is 3 chars and 'tar.gz' is 5 so we cannot set a limit. add to this
    # list if other types should be supported as well as the necessary
    # decompression command below.
    allowable_file_exts = re.compile(r'tgz$|tar\.gz$|zip$')

    decompression_cmds = {'tar.gz': ['tar', '-xzf'],
                          'tgz': ['tar', '-xzf'],
                          'zip': ['unzip', '-oqq']}

    # ensure machine has the correct prerequisite programs, files, etc.
    [necessary_programs.add(cmd.split()[0])
     for cmd in [rat_cmd, compile_cmd, test_cmd]]

    check_for_programs(necessary_programs)

    # download all necessary files into the staging directory
    if not os.path.exists(staging_dir):
        run_command(Error.MKDIR, ['mkdir', '-p', staging_dir])

    os.chdir(staging_dir)

    # default to assuming the 'KEYS' file is within the `release_url` directory
    if not keys_url:
        keys_url = release_url + '/KEYS'

    import_keys(keys_url)

    try:
        html = BeautifulSoup(urllib2.urlopen(release_url).read(), 'html.parser')
    except urllib2.URLError:
        pass

    package_list = [i.get('href') for i in html.find_all('a')
                    if allowable_file_exts.findall(i.get('href'))]

    if select_package:
        package_map = dict()
        for idx, package in enumerate(package_list):
            package_map[idx] = package
            
        # print the index and package in a pretty format
        for idx, package in package_map.iteritems():
            print '{}: {}'.format(idx, package)

        try:
            package_selection = int(raw_input('Your selection:'))
            package_list = [package_map[package_selection]]
        except ValueError:
            print 'value error'
        except KeyError:
            print 'key error'

    # for each package we want to test...
    for package in package_list:
        print package

        # grab the file extension found
        file_ext = allowable_file_exts.findall(package)[0]

        download_sourcecode(release_url + '/' + package)
        # the below files should always exist as mandated by the apache release
        download_sourcecode(release_url + '/' + package + '.asc')
        download_sourcecode(release_url + '/' + package + '.md5')
        download_sourcecode(release_url + '/' + package + '.sha')

        verify_asc(package)

        compare_digests(package, {'sha': sha512_digest_cmd,
                                  'md5': md5_digest_cmd})
'''
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
'''

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "noe"
