#!/usr/bin/env python
# Copyright: 2014 Dennis Schmalacker <github@progde.de>
# License: BSD 2-clause, see LICENSE for details.

"""
commandline client for bepasty-server
"""

from __future__ import print_function
import base64
import re
import os
import pwd
import sys
import errno
import codecs
import warnings
try:
    from ConfigParser import SafeConfigParser as ConfigParser, Error as ConfigParserError
except ImportError:
    # Python 3
    from configparser import ConfigParser, Error as ConfigParserError

import click
import magic
import requests
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    # Debian has unbundled urllib3 from requests
    from urllib3.exceptions import InsecureRequestWarning


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
LIFETIME_CHOICES = (
    'min', 'minutes', 'h', 'hours', 'd', 'days', 'w', 'weeks', 'm', 'months',
    'y', 'years', 'f', 'forever'
)
LIFETIME_NAMES = (
    'MINUTES', 'MINUTES', 'HOURS', 'HOURS', 'DAYS', 'DAYS', 'WEEKS', 'WEEKS',
    'MONTHS', 'MONTHS', 'YEARS', 'YEARS', 'FOREVER', 'FOREVER'
)
LIFETIME_MAPPING = dict(zip(LIFETIME_CHOICES, LIFETIME_NAMES))
CONFIG_DEFAULTS = dict(
    token='',
    url='',
    lifetime='1f',
    insecure=False
)
CONFIG_FILENAME = click.get_app_dir('bepasty-client-cli')


class LifetimeParamType(click.ParamType):
    name = 'lifetime'
    lifetime_regex = re.compile(r'^(\d*) *({})$'.format('|'.join(choice for choice in LIFETIME_CHOICES)))

    def convert(self, value, param, ctx):
        m = self.lifetime_regex.match(value)
        if m:
            result = m.groups()
            result = result[0].lstrip('0'), result[1]
            if not result[0]:
                if result[1] in ['f', 'forever']:
                    result = '1', result[1]
                else:
                    self.fail('Multiplier for the lifetime argument must be a positive integer.', param, ctx)
            return result
        else:
            self.fail('"%s" is not a valid lifetime.' % value, param, ctx)


def setup_config_parser(override=None):
    if not override:
        override = dict()
    config = ConfigParser()
    config.add_section('bepasty-client-cli')
    for k, v in CONFIG_DEFAULTS.items():
        v = override.get(k, v)
        config.set('bepasty-client-cli', k, str(v))
    return config


def write_configuration_file(config, filename=CONFIG_FILENAME):
    click.echo('Writing configuration to "{}".'.format(filename))
    try:
        os.makedirs(os.path.dirname(filename), 750)
    except EnvironmentError as exc:
        if exc.errno != errno.EEXIST:
            raise click.ClickException(str(exc))
    with codecs.open(filename, 'w', 'utf8') as fp:
        config.write(fp)


def setup_configuration(ctx, param, value):
    if any(option in sys.argv for option in ('-h', '--help', '--write-config')):
        # allow help message with faulty configuration file
        # allow to overwrite (faulty) configuration file
        ctx.default_map = CONFIG_DEFAULTS
        return value

    config = setup_config_parser()
    if value and not os.path.exists(value):
        raise click.UsageError('Cannot read configuration file "{}".'.format(value))
    try:
        config.read([value or CONFIG_FILENAME])
    except ConfigParserError as exc:
        raise click.UsageError('Error in configuration file: {}'.format(exc))
    ctx.default_map = dict()
    for option in CONFIG_DEFAULTS.keys():
        if option == 'insecure':
            try:
                ctx.default_map[option] = config.getboolean('bepasty-client-cli', option)
            except ValueError:
                raise click.UsageError('Error: Value for "{}" in {} must be one of {}.'.format(
                    option,
                    CONFIG_FILENAME,
                    ', '.join(('1', 'yes', 'true', 'on', '0', 'no', 'false', 'off'))))
        else:
            ctx.default_map[option] = config.get('bepasty-client-cli', option)
    return value


def shorten_homepath(homepath):
    try:
        return homepath.replace(pwd.getpwuid(os.getuid()).pw_dir, '~', 1)
    except:
        return homepath


@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument('filename', nargs=1, required=False)
@click.option(
    '-p',
    '--pass',
    'token',
    help='The token to authenticate yourself to the bepasty server')
@click.option(
    '-u',
    '--url',
    'url',
    help='base URL of the bepasty server')
@click.option(
    '-n',
    '--name',
    'fname',
    help='Filename for piped input.')
@click.option(
    '-L',
    '--lifetime',
    type=LifetimeParamType(),
    help='Lifetime for the file that is uploaded. Example: "-L 2d" (two days). If this '
         'option is not set, the uploads lifetime is "forever". Multiplier has to be '
         'a positive integer, Unit has to be one of these: "min" (minutes), "h" (hours), '
         '"d" (days), "w" (weeks), "m" (months), "y" (years), "f" (forever).')
@click.option(
    '-l',
    '--list',
    'list_pastes',
    is_flag=True,
    help='Lists all pastes on server (requires LIST permissions)')
@click.option(
    '-t',
    '--type',
    'ftype',
    help='Filetype for piped input. ' +
    'Give the value for the Content-Type header here, e.g. text/plain or image/png. ' +
    'If omitted, filetype will be determined by magic')
@click.option(
    '-i',
    '--insecure',
    help='Disable SSL certificate validation',
    is_flag=True)
@click.option(
    '--write-config',
    help='Write current command line arguments and defaults to configuration file and exit. Can be used '
         'together with -c to specify file to write to.',
    is_flag=True,
    default=False)
@click.option(
    '-c',
    '--config',
    'configfile',
    help='Specify configuration file to read from or write to (default is {}).'.format(shorten_homepath(CONFIG_FILENAME)),
    callback=setup_configuration,
    is_eager=True,
    type=click.Path())
def main(token, filename, fname, url, ftype, list_pastes, insecure, lifetime, write_config, configfile):
    url = url.rstrip("/")
    if write_config:
        lifetime = "".join(lifetime)
        write_configuration_file(setup_config_parser(locals()), configfile or CONFIG_FILENAME)
        sys.exit(0)
    if not url:
        raise click.UsageError('Please supply the URL of the bepasty server.')
    lifetime = (lifetime[0], LIFETIME_MAPPING[lifetime[1]])

    if list_pastes:
        print_list(token, url, insecure)
    else:
        upload(token, filename, fname, url, ftype, insecure, lifetime)


def _make_request(method, url, **kwargs):
    func = getattr(requests, method)
    try:
        if kwargs.get('verify', False):
            return func(url, **kwargs)
        else:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=InsecureRequestWarning)
                return func(url, **kwargs)
    except Exception as exc:
        print("Cannot {} {}".format(method, url))
        print(exc)
        sys.exit(1)


def print_list(token, url, insecure):
    from datetime import datetime
    response = _make_request(
        'get',
        '{}/apis/rest/items'.format(url),
        auth=('user', token),
        verify=not insecure
    )
    try:
        for k, v in response.json().items():
            meta = v['file-meta']
            if not meta:
                print("{:8}: BROKEN PASTE".format(k))
            else:
                print("{:8}: {} at {}".format(
                    meta['filename'],
                    "{}B".format(meta['size']) if meta['complete'] else 'INCOMPLETE',
                    datetime.fromtimestamp(meta['timestamp-upload']).strftime('%Y-%m-%d')))
    except Exception as e:
        print("cannot load json from response: {}".format(e))
        print("Original Response: {}".format(response))


def upload(token, filename, fname, url, ftype, insecure, lifetime):
    """
    determine mime-type and upload to bepasty
    """
    read_size = 1 * 1024 * 1024
    if filename:
        fileobj = open(filename, 'rb')
        filesize = os.path.getsize(filename)
        if not fname:
            fname = os.path.basename(filename)
        stdin = False
    else:
        fileobj = click.get_binary_stream('stdin')
        if not fname:
            fname = ''
        stdin = True

    # we use the first chunk to determine the filetype if not set
    first_chunk = fileobj.read(read_size)
    if not ftype:
        mime = magic.Magic(mime=True)
        ftype = mime.from_buffer(first_chunk).decode()

        if not ftype:
            ftype = 'text/plain'
            print('falling back to {}'.format(ftype))
        else:
            print('guessed filetype: {}'.format(ftype))
    else:
        print('using given filetype {}'.format(ftype))

    offset = 0
    trans_id = ''
    while True:
        if not offset:
            raw_data = first_chunk
        else:
            raw_data = fileobj.read(read_size)
        raw_data_size = len(raw_data)

        if not raw_data:
            break  # EOF
        if stdin:
            if raw_data_size < read_size:
                filesize = offset + raw_data_size
            else:
                filesize = offset + raw_data_size + 1

        payload = base64.b64encode(raw_data)

        headers = {
            'Content-Range': 'bytes %d-%d/%d' % (offset, offset + raw_data_size - 1, filesize),
            'Content-Type': ftype,
            'Content-Filename': fname,
            'Content-Length': str(len(payload)),  # rfc 2616 14.16
            'Maxlife-Unit': lifetime[1],
            'Maxlife-Value': str(lifetime[0]),
        }
        if trans_id != '':
            headers['Transaction-ID'] = trans_id
        response = _make_request(
            'post',
            '{}/apis/rest/items'.format(url),
            data=payload,
            headers=headers,
            auth=('user', token),
            verify=not insecure
        )
        offset += raw_data_size
        if response.status_code in (200, 201):
            sys.stdout.write(
                '\r%dB (%d%%) uploaded of %dB total.' %
                (offset, offset * 100 / filesize, filesize))
        if response.status_code == 200:
            pass
        elif response.status_code == 201:
            loc = response.headers['Content-Location']
            print('\nFile was successfully uploaded and can be found here:')
            print('{}{}'.format(url, loc))
            print('{}/{}'.format(url, loc.split('/')[-1]))
        else:
            print('An error occurred: %d %s' %
                  (response.status_code, response.text))
            return

        if response.headers['Transaction-ID']:
            trans_id = response.headers['Transaction-ID']


if __name__ == '__main__':
    main()
