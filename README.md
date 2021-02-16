# What is MacHound
MacHound is an extension to the Bloodhound audting tool allowing collecting and ingesting of Active Directory relationships on MacOS hosts.
MacHound collects information about logged-in users, and administrative group members on Mac machines and ingest the information into the Bloodhound database. 
In addition to using the HasSession and AdminTo edges, MacHound adds three new edges to the Bloodhound database:
* CanSSH - entity allowed to SSH to host
* CanVNC - entity allowed to VNC to host
* CanAE - entity allowed to execute AppleEvent scripts on host 

To read more about MacHound, refer to the [introduction post](https://medium.com/xm-cyber)

# Data Collection
## Logged-in users (HasSession)
MacHound uses the utmpx API to query currently active users and OpenDirectory and membership API to validate Active Directory users.

## Administrative Groups
MacHound collects Active Directory members of the following local administrative groups:

### admin
The local administrative groups, allowing for root operations.

### com.apple.access_ssh
Members of this local group are allowed to access the remote login service (SSH).

### com.apple.remote_ae
Members of this local group are allowed to remotely execute AppleEvent scripts.

### com.apple.access_screensharing
Members of this local group are allowed to access the screen sharing service (VNC)

# Components
MacHound is split into two main components: the collector and the ingestor.

### Collector
The MacHound collector is a Python3.7 scripts that run locally on Active Directory joined MacOS hosts.
The collector queries the local OpenDirectory and the Active Directory for information about priviliged users and groups.
The output of the execution is a JSON file that contains all the collected information.

### Ingestor
The MacHound ingestor is a Python3.7 script that parses the output JSON files (one per host), connects to the neo4j database and inserts the edges to the database.
The ingestor uses the neo4j library for Python to query information to and from the neo4j database.
The ingestor must be executed on a host that has TCP access to the neo4j database.

# Getting Started

## Requirements
MacHound requires Python3.7.
The ingestor requires the neo4j library for Python3.7.
‏
## Collector

### Deployment
The Collector should be deployed and executed locally on Macs. The output is stored locally and needs to be transfered to the host running the ingestor. The collector depends on builtin libraries in Python3.7  and does not require additional installations.
MacHound can be compiled as an Application using the py2app library to ease the deployment.

### Usage
The Collector takes no arguments by default queries all information, and writes the output file into ./output.json.
The Collector must be executed as a root user.
```
collector.py -o <output_file> -c <Admin,CanSSH,CanVNC,CanAE,HasSession> [-v] [-l log_file_path]
```

## Ingestor
The Ingestor should be deployed on a host that has direct TCP connection to Bloodhound's neo4j database, preferably locally on the neo4j database server to avoid security risks.
The ingestor requires the installation of neo4j driver for Python (see requirements file).

```
ingestor.py <url_to_neo4j> -u <username> -p <password> -i <json_folder>
```

# License
MacHound is released under the license. For more details see LICENSE.

# Contact Us
For any question, suggestion, bug reporting please feel free to contact at rony@xmcyber.com


