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

import ctypes
import logging
import os
import time
import codecs

_UTX_USERSIZE = 256
_UTX_IDSIZE = 4
_UTX_LINESIZE = 32
_UTX_HOSTSIZE = 256
ID_TYPE_UID = 0
ID_TYPE_GID = 1
NTSID_MAX_AUTHORITIES = 16

# Structs used for utmpx access

class timeval(ctypes.Structure):
    '''
    https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/gettimeofday.2.html
    
    struct timeval {
             time_t       tv_sec;   /* seconds since Jan. 1, 1970 */
             suseconds_t  tv_usec;  /* and microseconds */
     };
    '''
    _fields_ = [
                ("tv_sec",  ctypes.c_int64),
                ("tv_usec", ctypes.c_int32),
               ]

class utmpx(ctypes.Structure):
    '''
    https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getutxline.3.html

     struct utmpx {
             char ut_user[_UTX_USERSIZE];    /* login name */
             char ut_id[_UTX_IDSIZE];        /* id */
             char ut_line[_UTX_LINESIZE];    /* tty name */
             pid_t ut_pid;                   /* process id creating the entry */
             short ut_type;                  /* type of this entry */
             struct timeval ut_tv;           /* time entry was created */
             char ut_host[_UTX_HOSTSIZE];    /* host name */
             __uint32_t ut_pad[16];          /* reserved for future use */
     };
    '''
    _fields_ = [
                ("ut_user", ctypes.c_char*_UTX_USERSIZE),
                ("ut_id",   ctypes.c_char*_UTX_IDSIZE),
                ("ut_line", ctypes.c_char*_UTX_LINESIZE),
                ("ut_pid",  ctypes.c_int32),
                ("ut_type", ctypes.c_int16),
                ("ut_tv",   timeval),
                ("ut_host", ctypes.c_char*_UTX_HOSTSIZE),
                ("ut_pad",  ctypes.c_uint32*16),
               ]

# Types and Structs used to parse UUID to SID 
'''
https://github.com/s-u/uuid/blob/master/src/uuid.h#L44

typedef unsigned char uuid_t[16];
'''
uuid_t = ctypes.c_ubyte*16
uid_t = ctypes.c_uint32

class nt_sid_t(ctypes.Structure):

    '''
    https://git.privacyone.io/useful/macos-sdk/-/blob/5047b3b4be3da2a9e37d154205a448ef6b6b2a69/MacOSX10.8.sdk/usr/include/ntsid.h

    #define NTSID_MAX_AUTHORITIES 16

    typedef struct {
        u_int8_t		sid_kind;
        u_int8_t		sid_authcount;
        u_int8_t		sid_authority[6];
        u_int32_t		sid_authorities[NTSID_MAX_AUTHORITIES];
    } nt_sid_t;
    '''
    _fields_ = [('sid_kind',ctypes.c_uint8),
                 ('sid_authcount',ctypes.c_uint8),
                 ('sid_authority',ctypes.c_uint8 * 6),
                 ('sid_authorities', ctypes.c_uint32 * NTSID_MAX_AUTHORITIES)]

    def to_string(self):
        authorities = "-".join(["%d"%x for x in self.sid_authorities]).replace("-0","")
        return "S-{0}-{1}-{2}".format(self.sid_kind,self.sid_authcount, authorities)

class SystemLib(object):
    
    def __init__(self):

        self._system_lib = ctypes.CDLL(ctypes.util.find_library("System"))

        # System lib functions used by UUID -> SID
        self.uuid_parse = self._system_lib.uuid_parse
        self.uuid_clear = self._system_lib.uuid_clear
        self.mbr_uuid_to_sid = self._system_lib.mbr_uuid_to_sid
        self.mbr_uuid_to_id = self._system_lib.mbr_uuid_to_id

        # System lib functions used for utmpx parsing
        self.setutxent_wtmp = self._system_lib.setutxent_wtmp
        self.getutxent = self._system_lib.getutxent
        self.getutxent.restype = ctypes.POINTER(utmpx)
        self.endutxent = self._system_lib.endutxent
        self.mbr_string_to_sid = self._system_lib.mbr_string_to_sid

    def uuid_to_sid(self, uuid):

        logging.debug("_uuid_to_sid with UUID - {0} started".format(uuid))

        # Create uuid instance
        current_uuid_t = uuid_t()

        # Call the clear function for the uuid instance
        self.uuid_clear(current_uuid_t)
        
        # Parse the UUID in its original form to the SID
        if 0 != self.uuid_parse(bytes(uuid, encoding="ascii"), current_uuid_t):
            logging.error("uuid_parse on UUID {0} failed".format(uuid))
            raise OSError("uuid_parse failed on UUID {0}".format(uuid))
        output_sid = nt_sid_t()

        # mbr_uuid_to_sid(const uuid_t uu, nt_sid_t *sid); 
        retval = self.mbr_uuid_to_sid(current_uuid_t, ctypes.byref(output_sid))
        if 0 != retval:
            logging.error("mbr_uuid_to_sid for UUID {0} failed with error {1}".format(uuid, retval))

        sid_string = output_sid.to_string()
        logging.debug("_uuid_to_sid with [UUID - {0}] = [SID - {1}] completed".format(uuid, sid_string))

        return sid_string

    def uuid_to_id(self, uuid):

        # mbr_uuid_to_id(uuid_t uu, uid_t* id, int* id_type);
        uid = uid_t()
        id_type = ctypes.c_int
        logging.debug("_uuid_to_id with UUID - {0} started".format(uuid))

        # Create uuid instance
        current_uuid_t = uuid_t()

        # Call the clear function for the uuid instance
        self.uuid_clear(current_uuid_t)
        
        # Parse the UUID in its original form to the SID
        if 0 != self.uuid_parse(bytes(uuid, encoding="ascii"), current_uuid_t):
            logging.error("uuid_parse on UUID {0} failed".format(uuid))
            raise OSError("uuid_parse failed on UUID {0}".format(uuid))
        
        retval = self.mbr_uuid_to_id(current_uuid_t, ctypes.byref(uid), ctypes.byref(id_type))

        if 0 != retval:
            logging.error("mbr_uuid_to_sid for UUID {0} failed with error {1}".format(uuid, retval))
            raise OSError("mbr_uuid_to_id failed on UUID {0}".format(uuid))

        return id_type

    def get_gui_sessions(self):

        # initialize
        login_list = []
        self.setutxent_wtmp(0)
        entry = self.getutxent()
        while entry:
            e = entry.contents
            entry = self.getutxent()
            if e.ut_user == b"":
                continue
            logging.debug("login: {0} - {1} - {2}".format(e.ut_user, e.ut_line, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.ut_tv.tv_sec))))
            login_list.append((codecs.decode(e.ut_user), time.localtime(e.ut_tv.tv_sec)))
        # finish
        self.endutxent()
        return login_list