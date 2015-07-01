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
    'Specified as file extension. E.g. png, txt, mp3. ' +
    'If omitted, filetype will be determined by magic')
def main(token, filename, fname, url, ftype):
    """
    determine mime-type and upload to bepasty
    """
    if filename:
        fileobj = open(filename, 'rb')
        filesize = os.path.getsize(filename)
        if not fname:
            fname = filename
    else:
        data = click.get_binary_stream('stdin').read()  # XXX evil for big stuff
        fileobj = BytesIO(data)
        filesize = len(data)
        if not fname:
            fname = ''

    if not ftype:
        mime = magic.Magic(mime=True)
        ftype = mime.from_buffer(fileobj.read(1024)).decode()
        fileobj.seek(0)
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
        read_size = 1 * 1024 * 1024
        raw_data = fileobj.read(read_size)
        if not raw_data:
            break  # EOF
        raw_data_size = len(raw_data)

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
            auth=('user', token))
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
