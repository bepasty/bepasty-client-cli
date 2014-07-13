# Copyright: 2014 Dennis Schmalacker <github@progde.de>
# License: BSD 2-clause, see LICENSE for details.

"""
bepasty-server commandline interface
"""

import os, sys, base64, pprint
from mimetypes import guess_type
import requests

import click

@click.command()
@click.option('-f', '--file', 'fileobj', help='File to be uploaded to a bepasty-server. If this is omitted stdin is read.')
@click.option('-n', '--name', 'fname', help='Filename for piped input.')
@click.option('-t', '--type', 'ftype', help='Filetype for piped input. Specified as file extension. E.g. png, txt, mp3...'
                                + ' If omitted, filetype will be destinguised by filename')
def main(fileobj, fname, ftype):

    pretty = pprint.PrettyPrinter()

    if fileobj:
        fileobj = open(fileobj, 'rb')
        filesize = os.path.getsize(os.path.abspath(fileobj.name))
        if not fname:
            fname = fileobj.name
        stdin = False

    else:
        fileobj = click.get_binary_stream('stdin')
        if not fname:
            fname = ''
        stdin = True

    if not ftype:
        ftype, enc = guess_type(fname)
        if not ftype:
            ftype = 'application/octet-stream'

    offset = 0
    trans_id = ''
    while True:
        read_size = 1 * 1024 * 1024
        raw_data = fileobj.read(read_size)
        raw_data_size = len(raw_data)

        payload = base64.b64encode(raw_data)

        if stdin:
            if raw_data_size < read_size:
                filesize = offset + raw_data_size
            else:
                filesize = offset + raw_data_size + 1

        headers = {
            'content-range': ('bytes %d-%d/%d' % (offset, offset+raw_data_size-1, filesize)),
            'content-type': ftype,
            'content-filename': fname,
            }
        headers['Content-Length'] = filesize
        if not trans_id == '':
            headers['Transaction-ID'] = trans_id

        response = requests.post('http://localhost:5000/api/v1/items', data=payload, headers=headers, auth=('user','foo'))
        offset = offset + raw_data_size
        if response.headers['Transaction-ID']:
            trans_id = response.headers['Transaction-ID']

        if raw_data_size < read_size:
            break



if __name__ == '__main__':
    main()
