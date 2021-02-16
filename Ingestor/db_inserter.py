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

import neo4j
import os
import logging
import json
import argparse


logging.basicConfig(level=logging.DEBUG)

CREATE_RELATIONSHIP         = "MATCH (a:Computer {{ objectid: $computer_sid }}),(b:{ad_member_type} {{ objectid: $ad_member_sid }}) MERGE (b)-[r:{connection_type}]->(a) RETURN a.name, type(r), b.name"
CREATE_SESSION              = "MATCH (a:Computer { objectid: $computer_sid }),(b:User { objectid: $ad_member_sid }) MERGE (a)-[r:HasSession]->(b) RETURN a.name, type(r), b.name"
GET_MACHINE_QUERY           = "MATCH (host:Computer) WHERE host.objectid = $smb_sid RETURN host.name"
GET_DOMAIN_OBJECT_QUERY     = "MATCH (domainobject:{ad_member_type}) WHERE domainobject.objectid = $smb_sid RETURN domainobject.name"

class MachoundIngestor(object):

    def __init__(self,address = "neo4j://localhost:7687", auth = ('username','password')):
        self.driver = neo4j.GraphDatabase.driver(address, auth=auth)

    def close_session(self):
        self.driver.close()

    @staticmethod
    def add_user_connection(tx, computer_sid, ad_member_sid, ad_member_type, connection_type):
        query = CREATE_RELATIONSHIP.format(**{"ad_member_type":ad_member_type,"connection_type":connection_type})
        tx.run(query, computer_sid=computer_sid, ad_member_sid=ad_member_sid)

    @staticmethod
    def get_computer_instance(tx, smb_sid):
        output = []
        for record in tx.run(GET_MACHINE_QUERY, smb_sid=smb_sid):
            print(record["host.name"])
            output.append(record)
        return output

    @staticmethod
    def get_adobject_instance(tx, smb_sid, ad_member_type):
        output = []
        query = GET_DOMAIN_OBJECT_QUERY.format(**{"ad_member_type":ad_member_type})
        for record in tx.run(query, smb_sid=smb_sid):
            print(record["domainobject.name"])
            output.append(record)
        return output


    @staticmethod
    def add_user_session(tx, computer_sid, ad_member_sid):
        tx.run(CREATE_SESSION, computer_sid=computer_sid, ad_member_sid=ad_member_sid)

    def parse_json(self, json_content):
        logging.debug("Starting neo4j session")
        db_session = self.driver.session()

        logging.info("Now parsing json for hostname {name} with smb sid {objectid}".format(**json_content['Properties']))
        host_name = json_content['Properties']['name']
        host_smbsid = json_content['Properties']['objectid']
        if [] == db_session.read_transaction(self.get_computer_instance,host_smbsid):
            logging.error("SMB Sid {0} was not found in the neo4j database".format(host_smbsid))
            return None

        # Parse Sessions
        for user_smbsid in json_content['Sessions']:
            if [] == db_session.read_transaction(self.get_adobject_instance,user_smbsid, "User"):
                logging.error("User with SMB Sid {0} was not found in the neo4j database".format(user_smbsid))
                continue
            db_session.write_transaction(self.add_user_session, host_smbsid, user_smbsid)

        # Parse Admin groups
        for admin_type in json_content['admin_groups']:
            for object_content in json_content['admin_groups'][admin_type]:
                object_type = object_content['MemberType']
                object_sid = object_content['MemberId']
                if [] == db_session.read_transaction(self.get_adobject_instance,object_sid, object_type):
                    logging.error("{0} with SMB Sid {1} was not found in the neo4j database".format(object_type, object_sid))
                    continue
                db_session.write_transaction(self.add_user_connection, host_smbsid, object_sid, object_type, admin_type)


def run_ingestor(json_folder, neo4j_address, neo4j_auth):

    ingestor = MachoundIngestor(neo4j_address, neo4j_auth)

    for root, dirs, files in os.walk(json_folder):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            logging.debug("Now parsing {0}".format(full_path))
            if not file_name.endswith("json"):
                logging.warn("File {0} is not a json and was ignored".format(full_path))
            with open(full_path,'r') as fp:
                json_content = json.load(fp)
                logging.debug("Json content was read successfully")
            ingestor.parse_json(json_content)
            
    ingestor.close_session()


def main():

    logging.basicConfig(level=logging.INFO)
    argparser = argparse.ArgumentParser(add_help=True, description='MacHound Python Collector.', formatter_class=argparse.RawDescriptionHelpFormatter)

    argparser.add_argument('-a',
                           '--address',
                           action='store',
                           default="bolt://localhost:7687",
                           help="Path to the Neo4j server (default is bolt://localhost:7687)")

    argparser.add_argument('-i',
                           '--inputfolder',
                           action='store',
                           default='./output',
                           help="Path to the input json folder (defaults is ./output)")

    argparser.add_argument('-u',
                           '--username',
                           action='store',
                           default='neo4j',
                           help="Username to the neo4j database")

    argparser.add_argument('-p',
                           '--password',
                           action='store',
                           default='neo4j',
                           help="Password to the neo4j database")

    argparser.add_argument('-v',
                           action='store_true',
                           help='Enable verbose output')

    
    # Get commandline arguments
    args = argparser.parse_args()
    neo4j_auth = (args.username,args.password)
    run_ingestor(args.inputfolder, args.address, neo4j_auth)
            

if "__main__" == __name__:
    main()