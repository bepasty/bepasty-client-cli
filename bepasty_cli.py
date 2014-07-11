# Copyright: 2014 Dennis Schmalacker <github@progde.de>
# License: BSD 2-clause, see LICENSE for details.

"""
bepasty-server commandline interface
"""

import os, argparse, sys, base64
import requests


def main():
    argparser = argparse.ArgumentParser(prog='bepasty')
    argparser.add_argument('-f','--file', type=argparse.FileType('rb'), help='File to upload to bepasty')
    argparser.add_argument('-n','--name', help='Name of the uploaded file')
    argparser.add_argument('-t','--type', help='Type if the uploaded file')

    args = argparser.parse_args()

    print args

    if args.file:
        offset = 0
        filesize = os.path.getsize(os.path.abspath(args.file.name))
        trans_id = ''
        print offset, filesize
        while offset < filesize:
            read_size = min(1 * 1024 * 1024, filesize - offset)
            payload = base64.b64encode(args.file.read(read_size))
            headers = {'content-length':filesize,
                        'content-range':('bytes %d-%d/%d' % (offset, offset+read_size-1, filesize)),
                        'content-type':'text/plain',
                        'content-filename':args.file.name,
                        'Transaction-ID': trans_id}

            response = requests.post('http://localhost:5000/api/v1/items', data=payload, headers=headers, auth=('user','foo'))
            offset = offset + read_size
            trans_id = response.headers['Transaction-ID']
            print response.request.headers
            print response.headers, response.text
    else:
        print sys.stdin.buffer.read(16*1024*1024)

if __name__ == '__main__':
    main()
