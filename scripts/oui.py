#!/usr/bin/env python

_DESCRIPTION = '''Download and parse a listing of Organizationally unique
identifiers, then export the listing as a Bro input file. This can then be
used with the OUI module to allow for OUI lookups in Bro.
'''

import re
import requests
import os
import shutil

from argparse import ArgumentParser
from tempfile import NamedTemporaryFile

# IEEE publishes a list of OUIs. Unfortunately, this URL is not currently
# available over HTTPS
_IEEE_OUI_LIST = 'http://standards-oui.ieee.org/oui.txt'

def main(fpath):

    # retrieve the IEEE OUI list
    resp = requests.get(_IEEE_OUI_LIST, stream=True)

    if resp.status_code != 200:
        os.exit(1)

    # pull out the 'hex' line from the ieee oui list
    parser = b'^(.*?)\s.*?\(hex\)\t\t(.*?)$'

    with NamedTemporaryFile(mode='w', delete=False) as f:
        temp_file_name = f.name

        print("#fields\toui\tvendor", file=f)
        # iterate the ouis returned and parse them into a bro script
        for line in resp.iter_lines():
            match = re.search(parser, line)

            if match:
                oui = match.group(1)
                vendor = match.group(2)
                oui = oui.replace(b'-', b':')

                print('{0}\t{1}'.format(oui.decode('utf-8').lower(), 
                    vendor.decode('utf-8')), file=f)

    shutil.move(temp_file_name, fpath)

if __name__ == '__main__':
    p = ArgumentParser(description=_DESCRIPTION)
    p.add_argument('path',
                    help='Where to place the exported input file.')
    args = p.parse_args()
    main(args.path)