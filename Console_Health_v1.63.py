# Copyright 2019-2020 Sophos Limited
#
# Licensed under the GNU General Public License v3.0(the "License"); you may
# not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
# https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Console_Health_v1.63
#
# Outputs csv file containing full inventory and health status of all devices in Sophos Central
#
#
# By: Michael Curtis and Robert Prechtel
# Date: 29/5/2020
# Version 1.63
# README: This script is an unsupported solution provided by
#           Sophos Professional Services

import requests
import csv
import configparser
# Import datetime modules
from datetime import date
from datetime import datetime
#Import OS to allow to check which OS the script is being run on
import os
# Get todays date and time
today = date.today()
now = datetime.now()
timestamp = str(now.strftime("%d%m%Y_%H-%M-%S"))
# This list will hold all the computers
list_of_machines_in_central = []

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    # headers is used to get data from Central
    headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    # post headers is used to post to Central
    post_headers = {'Authorization': f"Bearer {json_token['access_token']}",
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
    return headers, post_headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    # Oraganization_Type = whoami["idType"]
    organizationID = whoami["id"]
    # Get the tennant Region
    regionURL = whoami['apiHosts']["dataRegion"]
    return organizationID, regionURL

def get_all_computers(tenant_token, url, name,tenant_url):
    # Get all Computers from sub estates
    computers_url = url
    # Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        # Tenant to be searched
        tenant_id = tenant_token
        # Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = tenant_id
        # Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        # Convert to JSON
        computers_json = request_computers.json()
        # Set the keys you want in the list
        computer_keys = ('id', 'hostname', 'lastSeenAt', 'threats', 'service_health', 'health', 'tamperProtectionEnabled', 'ipv4Addresses', 'associatedPerson', 'Sub Estate', 'os', 'majorVersion', 'type')
        # Add the computers to the computers list
        for all_computers in computers_json["items"]:
            # Make a temporary Dictionary to be added to the sub estate list
            computer_dictionary = {key:value for key, value in all_computers.items() if key in computer_keys}
            # If no hostname is returned add unknown
            if 'hostname' not in computer_dictionary.keys():
                computer_dictionary['hostname'] = 'Unknown'
            # This line allows you to debug on a certain computer. Add computer name
            if 'SEC-Clean' == computer_dictionary['hostname']:
                print('Add breakpoint here')
            # Sends the last seen date to get_days_since_last_seen and converts this to days
            computer_dictionary['Last_Seen'] = get_days_since_last_seen(computer_dictionary['lastSeenAt'])
            # Checks if Health have been returned
            if 'health' in computer_dictionary.keys():
                # Checks if Health Status has been returned. If not adds investigate
                if 'status' in computer_dictionary['health']['services']:
                    computer_dictionary['service_health'] = computer_dictionary['health']['services']['status']
                else:
                    computer_dictionary['service_health'] = 'investigate'
                # Checks if Threat Status has been returned. If not adds investigate
                if 'status' in computer_dictionary['health']['threats']:
                    computer_dictionary['threats'] = computer_dictionary['health']['threats']['status']
                else:
                    computer_dictionary['threats'] = 'investigate'
                # Any filtering you want to do has to done above this line as it changes the health dictionary
                computer_dictionary['health'] = computer_dictionary['health']['overall']
            # Check to see if the key value for platform returns Mac. If so make the OS key equal the Mac version else return the platform name for Windows and Linx
            if 'macOS' in computer_dictionary['os']['platform']:
                 computer_dictionary['os'] = f"{str(computer_dictionary['os']['platform'])}{' '}{str(computer_dictionary['os']['majorVersion'])}{'.'}{str(computer_dictionary['os']['minorVersion'])}{'.'}{str(computer_dictionary['os']['build'])}"
            else:
                 computer_dictionary['os'] = computer_dictionary['os']['name']
            # If a user is returned tidy up the value. It is checking for the key being present
            if 'associatedPerson' in computer_dictionary.keys():
                 computer_dictionary['associatedPerson'] = computer_dictionary['associatedPerson']['viaLogin']
            # Checks to see if there is a encryption status
            if 'encryption' in all_computers.keys():
                # I don't think this is the best code. The encryption status is a dictionary, with a list, another dictionary, then the status
                # At present this just reports one drive. The first one in the list. 0
                encryption_status = all_computers['encryption']['volumes']
                # Checks to see if the volume is returned correctly. Sometimes encryption is returned with no volume
                try:
                    volume_returned = encryption_status[0]
                    computer_dictionary['encryption'] = (encryption_status[0]['status'])
                except IndexError:
                    computer_dictionary['encryption'] = 'Unknown'
                # computer_dictionary['encryption'] = (encryption_status[0]['status'])
            # Checks to see if the machine is in a group
            if 'group' in all_computers.keys():
                computer_dictionary['group'] = all_computers['group']['name']
            #Get installed products
            #Check if assignedProducts exists. It only works with Windows machines
            if 'assignedProducts' in all_computers.keys():
                for products in all_computers['assignedProducts']:
                    #This loops through the product names and gets the versions. We may not add these to the report
                    product_names = products['code']
                    computer_dictionary[product_names] = products['status']
                    product_version_name = f"v_{product_names}"
                    if products['status'] == 'installed' and versions == 1:
                        computer_dictionary[product_version_name] = products['version']
            computer_dictionary['Machine_URL'], new_machine_id = make_valid_client_id(computer_dictionary['type'],computer_dictionary['id'])
            # This is for future use
            # Check to see if threat health is good. If no, go and find out why
            if 'threats' in computer_dictionary.keys():
                if 'good' != computer_dictionary['threats']:
                    get_threats(computer_dictionary['hostname'], computers_url, new_machine_id, tenant_url,headers, post_headers)
            # Adds the sub estate name to the computer dictionary
            computer_dictionary['Tenant'] = name
            list_of_machines_in_central.append(computer_dictionary)
        # Check to see if you have more than 50 machines by checking if nextKey exists
        # We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = f"{url}{'?pageFromKey='}{next_page}"
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

def get_days_since_last_seen(report_date):
    # https://www.programiz.com/python-programming/datetime/strptime
    # Converts report_date from a string into a DataTime
    convert_last_seen_to_a_date = datetime.strptime(report_date, "%Y-%m-%dT%H:%M:%S.%f%z")
    # Remove the time from convert_last_seen_to_a_date
    convert_last_seen_to_a_date = datetime.date(convert_last_seen_to_a_date)
    # Converts date to days
    days = (today - convert_last_seen_to_a_date).days
    return days

def get_threats(hostname, computer_url, endpoint_id, tenant_url, headers, post_headers):
    # For future use
    endpoint_id2 = 'f9955516-ff69-4925-bbe4-d5e08932d7cb'
    full_enpoint_url = f"{tenant_url}{'/common/v1/alerts/'}{endpoint_id}"
    # https://api-{dataRegion}.central.sophos.com/common/v1/alerts/id
    request_threat = requests.get(full_enpoint_url, headers=headers)
    # Convert to JSON
    threat_json = request_threat.json()
    print('')

def make_valid_client_id(os,machine_id):
    # Characters to be removed
    # https://central.sophos.com/manage/server/devices/servers/b10cc611-7805-7419-e9f0-46947a4ab60e/summary
    # https://central.sophos.com/manage/endpoint/devices/computers/60b19085-7bbf-44ff-3a67-e58a3c4e14b1/summary
    Server_URL = 'https://central.sophos.com/manage/server/devices/servers/'
    Endpoint_URL = 'https://central.sophos.com/manage/endpoint/devices/computers/'
    # Remove the - from the id
    remove_characters_from_id = ['-']
    for remove_each_character in remove_characters_from_id:
        machine_id = machine_id.replace(remove_each_character, '')
    new_machine_id = list(machine_id)
    # Rotates the characters
    new_machine_id[::2], new_machine_id[1::2] = new_machine_id[1::2], new_machine_id[::2]
    for i in range(8, 28, 5):
        new_machine_id.insert(i, '-')
    new_machine_id = ''.join(new_machine_id)
    if os == 'computer':
        machine_url = f"{Endpoint_URL}{new_machine_id}"
    else:
        machine_url = f"{Server_URL}{new_machine_id}"
    return (machine_url,new_machine_id)

def read_config():
    config = configparser.ConfigParser()
    config.read('console_config.config')
    config.sections()
    ClientID = config['DEFAULT']['ClientID']
    ClientSecret = config['DEFAULT']['ClientSecret']
    ReportName = config['REPORT']['ReportName']
    ReportFilePath = config['REPORT']['ReportFilePath']
    ConsoleName = config['REPORT']['ConsoleName']
    # Checks if the last character of the file path contanins a \ or / if not add one
    if ReportFilePath[-1].isalpha():
        if os.name != "posix":
            ReportFilePath = ReportFilePath + "\\"
        else:
            ReportFilePath = f"{ReportFilePath}{'/'}"
    return(ClientID,ClientSecret,ReportName,ReportFilePath,ConsoleName)

def report_field_names():
        #Customise the column headers and column order
    versions = 0
    if versions == 0:
        fieldnames = ['Machine URL',
                      'Tenant',
                      'Hostname',
                      'Type',
                      'OS',
                      'Encrypted Status',
                      'Last Seen Date',
                      'Days Since Last Seen',
                      'Health',
                      'Threats',
                      'Service Health',
                      'Tamper Enabled',
                      'Group',
                      'Core Agent',
                      'Endpoint Protection',
                      'Intercept X',
                      'Device Encryption',
                      'MTR',
                      'IP Addresses',
                      'Last User',
                      'id',
                      ]
        order = ['Machine_URL',
                 'Tenant',
                 'hostname', 'type',
                 'os',
                 'encryption',
                 'lastSeenAt',
                 'Last_Seen',
                 'health',
                 'threats',
                 'service_health',
                 'tamperProtectionEnabled',
                 'group',
                 'coreAgent',
                 'endpointProtection',
                 'interceptX',
                 'deviceEncryption',
                 'mtr',
                 'ipv4Addresses',
                 'associatedPerson',
                 'id',
                 ]
    else:
        fieldnames = ['Machine URL',
                      'Tenant',
                      'Hostname',
                      'Type',
                      'OS',
                      'Encrypted Status',
                      'Last Seen Date',
                      'Days Since Last Seen',
                      'Health', 'Threats',
                      'Service Health',
                      'Tamper Enabled',
                      'Group',
                      'Core Agent',
                      'Core Agent Version',
                      'Endpoint Protection',
                      'Endpoint Protection Version',
                      'Intercept X',
                      'Intercept X Version',
                      'Device Encryption',
                      'Device Encryption Version',
                      'MTR',
                      'MTR Version',
                      'IP Addresses',
                      'Last User',
                      'id',
                      ]
        order = ['Machine_URL',
                 'Tenant',
                 'hostname',
                 'type',
                 'os',
                 'encryption',
                 'lastSeenAt',
                 'Last_Seen',
                 'health',
                 'threats',
                 'service_health',
                 'tamperProtectionEnabled',
                 'group',
                 'coreAgent',
                 'v_coreAgent',
                 'endpointProtection',
                 'v_endpointProtection',
                 'interceptX',
                 'v_interceptX',
                 'deviceEncryption',
                 'v_deviceEncryption',
                 'mtr',
                 'v_mtr',
                 'ipv4Addresses',
                 'associatedPerson',
                 'id',
                 ]
    return (fieldnames,order, versions)

def print_report():
    with open(full_report_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, order)
        dict_writer.writerows(list_of_machines_in_central)



clientID, clientSecret, report_name, report_file_path, console_name = read_config()
full_report_path = f"{report_file_path}{report_name}{timestamp}{'.csv'}"

token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers, post_headers = get_bearer_token(clientID, clientSecret, token_url)
# Get the tenantID
tenantID, tenant_url = get_whoami()
tenant_endpoint_url = f"{tenant_url}{'/endpoint/v1/endpoints'}"
fieldnames, order, versions = report_field_names()
get_all_computers(tenantID, tenant_endpoint_url, console_name,tenant_url)

print_report()
