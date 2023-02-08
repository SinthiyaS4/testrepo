####################################################
#                                                  #
#   Python script to extract ne Information        #
#                                                  #
####################################################

# !/usr/bin/python

# Importing the required modules
import configparser
import csv
import os

import requests
import sys
import logging

from utils import ne_logging

username = "admin"
password = "NokiaNsp1!"

""" Token Generation """
print("       Token Generation       ")

token_gen_url = "https://135.121.158.143/rest-gateway/rest/api/v1/auth/token"

# Form_data for token generation

data = {"grant_type", "client_credentials"}
headers = {"Content-Type": "application/json", "Authorization": "Basic YWRtaW46Tm9raWFOc3AxIQ=="}
token_gen = requests.post(url=token_gen_url, data=data, auth=(username, password), verify=False, headers=headers)
print("token_check : ", token_gen.status_code, token_gen.text)
if token_gen.status_code >= 299:
    print(token_gen.text)
    sys.exit()
else:
    token_gen = token_gen.json()
    print(token_gen)

""" Export the data """
print("       Export the data       ")
try:
    ne_config_file = "/var/temp/NE_Configuration.cf"
    ne_integration_file = "/var/temp/NE_Integration.cf"
    # ne_config_file = "C://Users//sinthiya//OneDrive - Nokia//Projects//NSP//Testing//Source" \
                    # "//conf//NE_Configuration.cf"
    # ne_integration_file = "C://Users//sinthiya//OneDrive - Nokia//Projects//NSP//Testing//Source" \
                      #    "//conf//NE_Integration.cf"

    config = configparser.ConfigParser()
    config.read_file(open(ne_config_file))
    config.read_file(open(ne_integration_file))

except configparser.MissingSectionHeaderError as e:
    logging.error('Check the section header in the configuration files')
    sys.exit(2)
else:
    ne_username = config.get('NE Integration Details', 'ne_username')
    ne_password = config.get('NE Integration Details', 'ne_password')
    servers = config.get('NE Integration Details', 'server')
    filterKey = config.get('NE Information Configuration', 'filterKey')
    filterValue = config.get('NE Information Configuration', 'filterValue')
    log_level = config.get('NE Information Configuration', 'log_level')
    ne_info_path = config.get('NE Information Configuration', 'ne_info_path')
    ne_info_req = config.get('NE Information Configuration', 'ne_info_req')
    ne_info_filename = config.get('NE Information Configuration', 'ne_info_filename')
    ne_log_dir = config.get('NE Information Configuration', 'ne_log_dir')
    ne_info_header_csv = config.get('NE Information Configuration', 'ne_info_header_csv')
    ne_info_search_header = config.get('NE Information Configuration', 'ne_info_search_header')

# Initializing the logger
logger = ne_logging(ne_log_dir, "NE_Netact_Migration.log", log_level)


# Function to make the ne request and extract the ne information
def ne_request(server, req_username, req_password):
    try:
        url_ne = ne_info_req.replace("(server)", server).replace("(filterKey)", filterKey). \
            replace("(filterValue)", filterValue)
        logger.info("Making the ne Information Request : %s" % url_ne)
        ne_response = requests.get(url_ne, data={'key': 'value'}, headers={'content-type': 'application/json'},
                                   auth=(req_username, req_password), verify=False)
        ne_info_json = ne_response.json()
        return ne_info_json
    except Exception as exp:
        logger.error(exp)
        sys.exit(2)


# Function to get key from JSON
def write_csv(ne_json_data):
    logger.info("Inside Write CSV Header")
    file_name = ne_info_filename
    file_path = os.path.join(ne_info_path, file_name)
    try:
        row_data = ne_json_data['data']
        data_file = open(file_path, 'w', newline='')
        csv_writer = csv.writer(data_file)
        count = 0
        for i in row_data:
            if count == 0:
                header = i.keys()
                csv_writer.writerow(header)
                count += 1
            csv_writer.writerow(i.values())
        data_file.close()
    except Exception as exp:
        logger.error(exp)
    logger.info("End of Write CSV File")


# Main method
def main():
    logger.info("Network Element Information Collection Started")
    try:
        ne_json_data = ne_request(servers, ne_username, ne_password)
        write_csv(ne_json_data)
    except Exception as exp:
        logger.error(exp)
    logger.info("Network Element Information Collection ended..")


if __name__ == '__main__':
    main()
