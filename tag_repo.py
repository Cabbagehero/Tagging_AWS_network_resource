# This file is to set some default lists.

import csv

Repos = []
with open("tag tree.csv") as file:
    reader = csv.DictReader(file)
    print(reader)
    for lines in reader:
        print(lines)
        Repos.append([lines['Project'], lines['App'], lines['Service']])

print(Repos)
#Repos = [['OPSNetwork', 'InfraOPS', 'VPC'], ['OPSNetwork', 'InfraOPS', 'squid']]
tag_default = [{'Key': 'Project', 'Value': 'OPSNetwork'}, {'Key': 'App', 'Value': 'InfraOPS'}, {'Key': 'Service', 'Value': 'VPC'}]
dx_tag_default = [{'key': 'Project', 'value': 'OPSNetwork'}, {'key': 'App', 'value': 'InfraOPS'}, {'key': 'Service', 'value': 'VPC'}]
region = ['ap-southeast-1']
account_profile = ['yding']
account_dictionary = {'yding': 126349779684}