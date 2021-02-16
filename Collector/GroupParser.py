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

import plistlib
import os
import ctypes
import ctypes.util
import codecs
import logging
import json
import time
import sys
import subprocess
import SystemLib

OD_MAIN_FOLDER = r"/var/db/dslocal/nodes/Default"
OD_GROUPS_FOLDER = os.path.join(OD_MAIN_FOLDER,"groups")
OD_USERS_FOLDER = os.path.join(OD_MAIN_FOLDER,"users")

class GroupParser(object):

    def __init__(self, system_lib = SystemLib.SystemLib(), groups_dir = OD_GROUPS_FOLDER, users_dir = OD_GROUPS_FOLDER):
        
        '''
         Create the users and groups dictionaries. This are stored as:
         group/user name : dictionary of the plist content
         The name is the file name as found in the OpenDirectory database folder
        '''
        self._users_dict = dict()
        self._groups_dict = dict()
        self._system_lib = system_lib

        # Get all users and group
        try:
            self._parse_groups(groups_dir)
            self._parse_users(users_dir)
        except PermissionError:
            logging.error("MacHound requires root permissions for execution. Please re-run the tools with root privileges")
            raise PermissionError("MacHound requires root permissions for execution. Please re-run the tools with root privileges") from None
        
    def get_all_group_members(self, group_plist):

        logging.debug("get_all_group_members started")

        # Contains the names of the local users who are members (direct or nested) of the group
        group_members = []
        activedirectory_sids = []

        # Get group direct members
        # Direct group members are stored under the 'groupmembers' property of the plist file.
        # Users are stored as their GUID, which can be either a local user or a remote user (Active Directory).
        # Local users (and mobile users) can be identified as they have a plist file, remote users have none.
        # Mobile users are treated as local users as their password can be out of sync from the Active Directory, for now we dont handle them
        # For remote users, the GUID is taken from the Active Directory. The value is stored under the 'objectGUID' property of the user in the Active Directory scheme.
        
        if 'groupmembers' in group_plist:
            direct_members = group_plist['groupmembers']
            for user_guid in direct_members:
                username = self.get_user_by_guid(user_guid)

                if username:
                    logging.debug("Found user name - {0}".format(username['name'][0]))

                    # Check if the user has the original_node_name, which how we identify mobile.
                    if "original_node_name" in username.keys():
                        logging.debug("Identified Mobile user, probably Domain User from {0}".format(username['original_node_name']))
                        user_sid = self._system_lib.uuid_to_sid(user_guid)
                        activedirectory_sids.append({"MemberId":user_sid,"MemberType":"User"})
                    
                    # Appen the name of the local user to the local users list
                    group_members.append(username['name'][0])

                else:
                    # This is probably an active directory user, should save this and test it against the AD.
                    logging.debug("Identified possible Network user - {0}".format(user_guid))
                    user_sid = self._system_lib.uuid_to_sid(user_guid)
                    activedirectory_sids.append({"MemberId":user_sid,"MemberType":"User"})

        # Get group nested members
        # Nested groups are stored under the 'nestedgroups' property of the plist file.
        # Groups are stored as their GUID, which can be either a local or a remote group (Active Directory).
        # Local groups can be identified as they have a plist file, remote groups have none.
        # For remote groups, the GUID is taken from the Active Directory. The value is stored under the 'objectGUID' property of the group in the Active Directory scheme.

        if 'nestedgroups' in group_plist:
            nested_groups = group_plist['nestedgroups']
            logging.debug("Identifying {0} nested groups".format(len(group_plist['nestedgroups'])))

            for nestedgroup_guid in nested_groups:
                group_instance = self.get_group_by_guid(nestedgroup_guid)
                if group_instance:
                    # Recursions are fun. This PoC does not test if there are loops and infinite recursions in the groups.
                    nestedgroup_members = self.get_all_group_members(group_instance)
                    if nestedgroup_members:
                        group_members+= nestedgroup_members['local']
                        activedirectory_sids+=nestedgroup_members['activedirectory_sids']

                else:
                    # This is probably an Active Directory group, should save this and test it against the AD.
                    logging.debug("Unknown group, probably Domain Group - {0}".format(nestedgroup_guid))
                    group_sid = self._system_lib.uuid_to_sid(nestedgroup_guid)
                    activedirectory_sids.append({"MemberId":group_sid,"MemberType":"Group"})
        logging.debug("get_all_group_members completed")
        return {"local":group_members, "activedirectory_sids":activedirectory_sids}

    def get_user_by_name(self, user_name):
        
        '''
         Get the user plist value from the scheme as parsed from the OD folder.
        
        '''

        if not user_name in self._users_dict:
            logging.warning("User name {0} was not found locally".format(user_name))
            return None

        return self._users_dict[user_name]
    
    def get_user_by_guid(self, user_guid):

        '''
         Get the user plist values from the scheme as parsed from the OD folder
         The GUID is stored as a property in the plist and therfore we have to iterate all dict members
         Its possible to index it better for performance
        
        '''

        for user_name in self._users_dict:
            if user_guid in self._users_dict[user_name]['generateduid']:
                return self._users_dict[user_name]

        logging.warning("User GUID {0} was not found".format(user_guid))
        return None

    def get_group_by_name(self, group_name):

        '''
         Get the group plist value from the scheme as parsed from the OD folder.
        '''
        
        if not group_name in self._groups_dict:
            logging.warning("Group name {0} was not found".format(group_name))
            return None
        
        return self._groups_dict[group_name]
    
    def get_group_by_guid(self, group_guid):

        '''
         Get the group plist values from the scheme as parsed from the OD folder
         The GUID is stored as a property in the plist and therfore we have to iterate all dict members
         Its possible to index it better for performance
        '''
        
        for group_name in self._groups_dict:
            if group_guid in self._groups_dict[group_name]['generateduid']:
                return self._groups_dict[group_name]
        logging.warning("Group GUID {0} was not found".format(group_guid))
        return None

    def _parse_plist_file(self, plist_path):

        '''
         parse the plist file to a dictionary.
         The plist files are stored in their binary format, not the xml format (tested on macOS 10.15, 10.16)
        '''
        
        if not os.path.exists(plist_path):
            logging.error("Plist file {0} was not found".format(plist_path))
            return None
        
        with open(plist_path,'rb') as fp:
            pl = plistlib.load(fp)

        return pl

    def _parse_users(self, users_path):
        '''
         Parses all plist files stored under the users directory in the OD scheme.
         The users are stored in a dictionary in the following format
         {name of the plistfile : plist dictionary}
        '''
        logging.debug("_parse_users started")
        for user_plist_path in os.listdir(users_path):
            username = os.path.splitext(user_plist_path)[0]
            self._users_dict[username] = self._parse_plist_file(os.path.join(users_path,user_plist_path))
        logging.debug("_parse_users completed")

    def _parse_groups(self, group_path):
        '''
         Parses all plist files stored under the users directory in the OD scheme.
         The users are stored in a dictionary in the following format
         {name of the plistfile : plist dictionary}
        '''

        logging.debug("_parse_groups started")
        for group_plist_path in os.listdir(group_path):
            group_name = os.path.splitext(group_plist_path)[0]
            self._groups_dict[group_name] = self._parse_plist_file(os.path.join(group_path,group_plist_path))
        logging.debug("_parse_groups completed")