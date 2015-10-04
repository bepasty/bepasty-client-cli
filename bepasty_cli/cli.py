#!/usr/bin/env python
# Copyright: 2014 Dennis Schmalacker <github@progde.de>
# License: BSD 2-clause, see LICENSE for details.

"""
commandline client for bepasty-server
"""

from __future__ import print_function
import base64
from io import BytesIO

import os
import sys

import click
import magic
import requests


@click.command()
@click.argument('filename', nargs=1, required=False)
@click.option(
    '-p',
    '--pass',
    'token',
    default='',
    help='The token to authenticate yourself to the bepasty server')
@click.option(
    '-u',
    '--url',
    'url',
    help='base URL of the bepasty server',
    default='http://localhost:5000')
@click.option('-n', '--name', 'fname', help='Filename for piped input.')
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
def main(token, filename, fname, url, ftype, insecure):
    """
    determine mime-type and upload to bepasty
    """
    read_size = 1 * 1024 * 1024
    if filename:
        fileobj = open(filename, 'rb')
        filesize = os.path.getsize(filename)
        if not fname:
            fname = filename
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
        ftype= mime.from_buffer(first_chunk).decode()

        if not ftype:
            print('falling back to {}'.format(ftype))
            ftype = 'text/plain'
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
            'Content-Range': ('bytes %d-%d/%d' %
                              (offset, offset + raw_data_size - 1, filesize)),
            'Content-Type': ftype,
            'Content-Filename': fname,
            'Content-Length': len(payload),  # rfc 2616 14.16
        }
        if trans_id != '':
            headers['Transaction-ID'] = trans_id
        response = requests.post(
            '{}/apis/rest/items'.format(url),
            data=payload,
            headers=headers,
            auth=('user', token),
            verify=(not insecure))
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
