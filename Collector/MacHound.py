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

import GroupParser
import SystemLib
import logging
import json
import subprocess
import codecs

ADMIN_GROUPS = {"AdminTo":"admin",
                "CanSSH":"com.apple.access_ssh",
                "CanVNC":"com.apple.access_screensharing",
                "CanAE":"com.apple.access_remote_ae"}

class MacHound():

    def __init__(self, edges_to_parse = ('HasSession','AdminTo','CanVNC','CanAE'),output_path = "./output.json"):
        
        # Init the System library wrapping class
        self._system_lib = SystemLib.SystemLib()
        
        # initiate the local OpenDirectory Parser 
        self._group_parser = GroupParser.GroupParser(system_lib=self._system_lib)

        # What edges MacHound will produce
        self._local_groups = list(edges_to_parse)

        # Mark sessions to be collected and remove the edge from the list
        if "HasSession" in edges_to_parse:
            self._do_login = True
            self._local_groups.remove("HasSession")

        # Path for the output json 
        self._output = output_path

        # Output to be dumped as json
        self._json_content = dict()


    def start(self):

        # Get the local SMBSID and computer name
        self._json_content['Properties'] = self._get_properties()

        # Get currently logged-in Active Directory Users
        if self._do_login:
            self._json_content['Sessions'] = self._get_logged_on_session()

        # Get Members of the local administrative groups
        if self._local_groups:
            self._json_content['AdminGroups'] = self._get_administrative_groups()

        # Dump the queried information to the output json file
        self._save_output()


    def _get_properties(self):

        output = dict()
        cmd_get_nodename_trustaccount = "echo show com.apple.opendirectoryd.ActiveDirectory | scutil"
        cmd_get_SMBSID_DNSName = 'dscl "{0}/All Domains" cat /Computers/{1}'
        
        # Execute the scutil command to get the TrustAccount and NodeName properties used to query the Active Directory
        # for the local machines SMBSID
        proc = subprocess.Popen(cmd_get_nodename_trustaccount, shell=True, bufsize=1, stdout=subprocess.PIPE)
        x = None
        y = None
        for line in proc.stdout:
            if b"NodeName" in line:
                x = codecs.decode(line).split(":")[1].strip()
            if b"TrustAccount" in line:
                y = codecs.decode(line).split(":")[1].strip()
        proc.stdout.close()
        if x is None or y is None:
            logging.error("Cannot parse Active Directory infromation, please check if computer is member of Active Directory")
            raise OSError("Cannot parse Active Directory infromation, please check if computer is member of Active Directory")
        
        # Execute the dscl command to get the SMBSID and DNS name of the local machine in Active Directory
        proc = subprocess.Popen(cmd_get_SMBSID_DNSName.format(x,y), shell=True, bufsize=1, stdout=subprocess.PIPE)
        
        for line in proc.stdout:
            if b"SMBSID" in line:
                output['objectid'] = codecs.decode(line).split(":")[1].strip()
            if b"DNSName" in line:
                output['name'] = codecs.decode(line).split(":")[1].strip()
        proc.stdout.close()

        return output

    def _get_logged_on_session(self):
        
        # Get session by parsing the utmpx file
        gui_sessions_list = self._system_lib.get_gui_sessions()

        session_list = []

        # Iterate all sessions and search for AD users
        for username, login_time in gui_sessions_list:
            user_plist = self._group_parser.get_user_by_name(username)

            # Network user - No plist file
            if user_plist == None:
                logging.warning("Network User login detected with username {0}".format(username))
                continue

            # Mobile User
            if "original_node_name" in user_plist.keys():
                logging.debug("Identified possible Network user login session - {0}".format(username))
                user_guid = user_plist['generateduid'][0]
                user_sid = self._system_lib.uuid_to_sid(user_guid)
                session_list.append(user_sid)

            # Local user are discarded
        
        return list(dict.fromkeys(session_list))

    def _get_administrative_groups(self):

        output = dict()

        for bh_connetion in self._local_groups:
            
            # Get the actual group name for the edge
            group_name = ADMIN_GROUPS[bh_connetion]

            # Get group instance from the OpenDirectory
            group_plist = self._group_parser.get_group_by_name(group_name)

            # Get all members of the group
            all_members = self._group_parser.get_all_group_members(group_plist)

            # Remove duplicates from list and add to the output
            output[bh_connetion] = [dict(t) for t in {tuple(d.items()) for d in all_members['activedirectory_sids']}]

        return output
        
    def _save_output(self):

        logging.info("Writing output to file {0}".format(self._output))
        with open(self._output,'w') as fd:
            json.dump(self._json_content, fd)

