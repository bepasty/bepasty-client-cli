#!/usr/bin/env python
# Copyright: 2014 Dennis Schmalacker <github@progde.de>
# License: BSD 2-clause, see LICENSE for details.

"""
bepasty-server commandline interface
"""

# for grandpa python
from __future__ import print_function
import os, sys, base64
from mimetypes import guess_type
import requests

#from tempfile import NamedTemporaryFile

import click

@click.command()
@click.argument('fileobj',nargs=1,required=False)
@click.option('-p', '--pass', 'token', default='', help='The token to authenticate yourself with the bepasty server')
@click.option('-n', '--name', 'fname', help='Filename for piped input.')
@click.option('-u','--url','url', help='URL to the base installation of bepasty',
        default='http://localhost:5000')
@click.option('-t', '--type', 'ftype', help='Filetype for piped input. Specified as file extension. E.g. png, txt, mp3...'
                                + ' If omitted, filetype will be destinguised by filename')
def main(token, fileobj, fname,url, ftype):

    if fileobj:
        fileobj = open(fileobj, 'rb')
        filesize = os.path.getsize(os.path.abspath(fileobj.name))
        if not fname:
            fname = fileobj.name
        stdin = False

    else:
        # tried to write stdin in tempfile and run guess_file, but guess_file
        # only seem to look on the file extension ...
        #tmpfile = NamedTemporaryFile(delete=False)
        fileobj = click.get_binary_stream('stdin')
        if not fname:
            fname = ''
            #fname = tmpfile.name
        #tmpfile.write(fileobj.read())
        #tmpfile.close()
        stdin = True

    if not ftype:
        # guess_type sucks buttocks, better use python-magic?
        ftype, enc = guess_type(fname)
        print('guessed filetype: {}'.format(ftype))
        if not ftype:
            #ftype = 'application/octet-stream'
            ftype = 'text/plain'
    else:
        print('using pre-defined filetype {}'.format(ftype))

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
        response = requests.post('{}/apis/rest/items'.format(url), data=payload, headers=headers, auth=('user',token))
        offset = offset + raw_data_size
        if not response.status_code in [200, 201]:
            print('An error ocurred: %s - %s' % (response.text, response.status_code))
            return
        elif response.status_code == 200:
            sys.stdout.write('\r%d Bytes already uploaded. That makes %d %% from %d Bytes' % ((offset/8), ((offset*100)/filesize), (filesize/8)))
        elif response.status_code == 201:
            print('\nFile sucessfully uploaded and can be found here:')
            print('{}{}'.format(url,response.headers['Content-Location']))
            print('{}/{}'.format(url,response.headers['Content-Location'].split('/')[-1]))


        if response.headers['Transaction-ID']:
            trans_id = response.headers['Transaction-ID']

        if raw_data_size < read_size:
            break



if __name__ == '__main__':
    main()
