'''
    This file is part of MacHound.

    MacHound is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    MacHound is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MacHound.  If not, see <https://www.gnu.org/licenses/>.

'''

import MacHound
import logging
import argparse
import os

LICENSE_TEXT = "MacHound  Copyright (C) 2021  XMCyber\n"+\
               "This program comes with ABSOLUTELY NO WARRANTY;\n"+\
               "This is free software, and you are welcome to redistribute it\n"+\
               "under certain conditions; see attached license for details.\n\n"

ACCEPTED_COLLECTORS = ('HasSession','AdminTo','CanSSH','CanVNC','CanAE')

def validate_collector_methods(methods):

    splitted_methods = methods.split(",")

    for method_name in splitted_methods:
        if not method_name in ACCEPTED_COLLECTORS:
            logging.error("Unknown collector {0} requested".format(method_name))
            raise ValueError("Unknown collector {0} requested".format(method_name))

    return splitted_methods

def main():

    logging.basicConfig(level=logging.INFO)
    
    # Print GPL3 license text
    print(LICENSE_TEXT)

    argparser = argparse.ArgumentParser(add_help=True, description='MacHound Python Collector.', formatter_class=argparse.RawDescriptionHelpFormatter)

    argparser.add_argument('-c',
                           '--collectors',
                           action='store',
                           default="HasSession,AdminTo,CanVNC,CanAE",
                           help="'What information should be collected from the list: HasSession,AdminTo,CanVNC,CanAE (default is all of the above)")

    argparser.add_argument('-o',
                           '--outputfile',
                           action='store',
                           default='./output.json',
                           help="Path to the output json file (defaults is ./output.json)")

    argparser.add_argument('-v',
                           action='store_true',
                           help='Enable verbose output')

    argparser.add_argument('-l',
                           '--logfile',
                           action='store',
                           default=None,
                           help='Path to log file.')

    args = argparser.parse_args()

   

    # Check if log file was requested
    if args.logfile:
        logger = logging.getLogger()
        fh = logging.FileHandler(args.logfile)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
     # Check if verbose enabled
    if args.v:
        logging.basicConfig(level=logging.DEBUG)
    # Validate requested methods and split to list
    methods = validate_collector_methods(args.collectors)

    # Get the output json path
    output_path = args.outputfile

    # Start collection
    machound = MacHound.MacHound(edges_to_parse=methods, output_path=output_path)
    machound.start()


if "__main__" == __name__:
    main()