import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError
import ipaddress
import tag_repo

def requesting_client(region):
    global client
    client = boto3.client(
        'ec2',
        aws_access_key_id="AKIAR225BHFSJTESW3QW",
        aws_secret_access_key="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",
        region_name=region,
    )
    global certificate_client
    certificate_client = boto3.client(
        'acm',
        aws_access_key_id="AKIAR225BHFSJTESW3QW",
        aws_secret_access_key="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",
        region_name=region,
    )
    global dx_client
    dx_client = boto3.client(
        'directconnect',
        aws_access_key_id="AKIAR225BHFSJTESW3QW",
        aws_secret_access_key="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",
        region_name=region,
    )

# requesting_client('ap-southeast-1')

def tagging_vpcs(region, account):
    vpcinfo = client.describe_vpcs()
    print(vpcinfo)
    vpc_num = len(vpcinfo['Vpcs'])
    # print(vpcinfo['vpcs'])
    for i in range(vpc_num):
        vpc_ids = []
        vpc_ids.append(vpcinfo['Vpcs'][i]['VpcId'])
        print(vpc_ids)
        if 'Tags' not in vpcinfo['Vpcs'][i]:
            print('There is no tags here in the vpc')
            client.create_tags(Resources=vpc_ids, Tags=tag_repo.tag_default)
            print('Add default tags')
        else:
            tag_number = len(vpcinfo['Vpcs'][i]['Tags'])
            # print(vpc_ids)
            # print(type(vpc_ids))
            # print('vpc ' + str(i) + ' has ' + str(tag_number) + ' tags')
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(tag_number):
                tag_entry = vpcinfo['Vpcs'][i]['Tags'][j]
                # print(vpcinfo['vpcs'][i]['Tags'][j])
                if tag_entry['Key'] == 'Project':
                    tag_project = tag_entry['Value']
                elif tag_entry['Key'] == 'App':
                    tag_app = tag_entry['Value']
                elif tag_entry['Key'] == 'Service':
                    tag_service = tag_entry['Value']
                else:
                    continue
            vpc_tags = [tag_project, tag_app, tag_service]
            if vpc_tags not in tag_repo.Repos:
                # print('Tag doesn\'t match tag tree')
                client.create_tags(Resources=vpc_ids, Tags=tag_repo.tag_default)
                print('Add default tags')
            else:
                print('Tag matches tag tree and already in there')

# tagging_vpcs('ap-southeast-1', 'yding')

def tagging_vpce(region, account):
    vpceinfo = client.describe_vpc_endpoints()
    print(vpceinfo)
    vpce_num = len(vpceinfo['VpcEndpoints'])
    # print(vpceinfo['vpce'])
    for i in range(vpce_num):
        vpce_ids = []
        tag_number = len(vpceinfo['VpcEndpoints'][i]['Tags'])
        vpce_ids.append(vpceinfo['VpcEndpoints'][i]['VpcEndpointId'])
        print(vpce_ids)
        # print(vpce_ids)
        # print(type(vpce_ids))
        # print('vpce ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = vpceinfo['VpcEndpoints'][i]['Tags'][j]
            # print(vpceinfo['vpce'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        vpce_tags = [tag_project, tag_app, tag_service]
        if vpce_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=vpce_ids, Tags=tag_repo.tag_default)
        else:
            print('Tag matches tag tree and already in there')

# tagging_vpce('ap-southeast-1')
def tagging_pxc(region, account):
    # pxc_client = boto3.client('sso')
    pxcinfo = client.describe_vpc_peering_connections()
    print(pxcinfo)
    pxc_num = len(pxcinfo['VpcPeeringConnections'])
    # print(pxcinfo['pxc'])
    for i in range(pxc_num):
        pxc_ids = []
        tag_number = len(pxcinfo['VpcPeeringConnections'][i]['Tags'])
        pxc_ids.append(pxcinfo['VpcPeeringConnections'][i]['VpcPeeringConnectionId'])
        print(pxc_ids)
        # print(pxc_ids)
        # print(type(pxc_ids))
        # print('pxc ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = pxcinfo['VpcPeeringConnections'][i]['Tags'][j]
            # print(pxcinfo['pxc'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        pxc_tags = [tag_project, tag_app, tag_service]
        if pxc_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=pxc_ids, Tags=tag_repo.tag_default)
        else:
            print('Tag matches tag tree and already in there')

# tagging_pxc('ap-southeast-1')
def tagging_vgw(region, account):
    vgwinfo = client.describe_vpn_gateways()
    print(vgwinfo)
    vgw_num = len(vgwinfo['VpnGateways'])
    # print(vgwinfo['vgw'])
    if vgw_num == 0:
        print('there is no vgw in this region and account')
    else:
        for i in range(vgw_num):
            vgw_ids = []
            tag_number = len(vgwinfo['VpnGateways'][i]['Tags'])
            vgw_ids.append(vgwinfo['VpnGateways'][i]['VpnGatewayId'])
            print(vgw_ids)
        # print(vgw_ids)
        # print(type(vgw_ids))
        # print('vgw ' + str(i) + ' has ' + str(tag_number) + ' tags')
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(tag_number):
                tag_entry = vgwinfo['VpnGateways'][i]['Tags'][j]
                # print(vgwinfo['vgw'][i]['Tags'][j])
                if tag_entry['Key'] == 'Project':
                    tag_project = tag_entry['Value']
                elif tag_entry['Key'] == 'App':
                    tag_app = tag_entry['Value']
                elif tag_entry['Key'] == 'Service':
                    tag_service = tag_entry['Value']
                else:
                    continue
            vgw_tags = [tag_project, tag_app, tag_service]
            if vgw_tags not in tag_repo.Repos:
                # print('Tag doesn\'t match tag tree')
                client.create_tags(Resources=vgw_ids, Tags=tag_repo.tag_default)
            else:
                print('Tag matches tag tree and already in there')

# tagging_vgw('ap-southeast-1', 'yding')
def tagging_subnets(region, account):
    # vpc_client = boto3.client('sso')
    subnetinfo = client.describe_subnets()
    subnet_num = len(subnetinfo['Subnets'])
    # print(subnetinfo['Subnets'])
    for i in range(subnet_num):
        subnet_ids = []
        subnet_ids.append(subnetinfo['Subnets'][i]['SubnetId'])
        print(subnet_ids)
        if 'Tags' not in subnetinfo['Subnets'][i]:
            print('There is no tags here in the vpc')
            client.create_tags(Resources=subnet_ids, Tags=tag_repo.tag_default)
            print('Add default tags')
        else:
            tag_number = len(subnetinfo['Subnets'][i]['Tags'])
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(tag_number):
                tag_entry = subnetinfo['Subnets'][i]['Tags'][j]
                # print(subnetinfo['Subnets'][i]['Tags'][j])
                if tag_entry['Key'] == 'Project':
                    tag_project = tag_entry['Value']
                elif tag_entry['Key'] == 'App':
                    tag_app = tag_entry['Value']
                elif tag_entry['Key'] == 'Service':
                    tag_service = tag_entry['Value']
                else:
                    continue
            subnet_tags = [tag_project, tag_app, tag_service]
            if subnet_tags not in tag_repo.Repos:
                # print('Tag doesn\'t match tag tree')
                client.create_tags(Resources=subnet_ids, Tags=tag_repo.tag_default)
            else:
                print('Tag matches tag tree and already in there')

def tagging_igws(region, account):
    # igw_client = boto3.client('sso')
    igwinfo = client.describe_internet_gateways()
    # print(igwinfo)
    igw_num = len(igwinfo['InternetGateways'])
    for i in range(igw_num):
        igw_ids = []
        tag_number = len(igwinfo['InternetGateways'][i]['Tags'])
        igw_ids.append(igwinfo['InternetGateways'][i]['InternetGatewayId'])
        print(igw_ids)
        # print(igw_ids)
        # print(type(igw_ids))
        # print('igw ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = igwinfo['InternetGateways'][i]['Tags'][j]
            # print(igwinfo['InternetGateways'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        igw_tags = [tag_project, tag_app, tag_service]
        if igw_tags not in tag_repo.Repos:
            print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=igw_ids, Tags=tag_repo.tag_default)
        else:
            print('Tag matches tag tree and already in there')

# tagging_igws('ap-southeast-1')
def tagging_eips(region, account):
    eipinfo = client.describe_addresses()
    print(eipinfo)
    eip_num = len(eipinfo['Addresses'])
    # print(subnetinfo['Subnets'])
    for i in range(eip_num):
        eip_ids = []
        eip_ids.append(eipinfo['Addresses'][i]['AllocationId'])
        if 'Tags' in eipinfo['Addresses'][i]:
            tag_number = len(eipinfo['Addresses'][i]['Tags'])
            public_ip = eipinfo['Addresses'][i]['PublicIp']
            print(public_ip)
            print(type(public_ip))
        # print(eip_ids)
        # print(subnet_ids)
        # print(type(subnet_ids))
        # print('Subnet ' + str(i) + ' has ' + str(tag_number) + ' tags')
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(tag_number):
                tag_entry = eipinfo['Addresses'][i]['Tags'][j]
            # print(subnetinfo['Subnets'][i]['Tags'][j])
                if tag_entry['Key'] == 'Project':
                    tag_project = tag_entry['Value']
                elif tag_entry['Key'] == 'App':
                    tag_app = tag_entry['Value']
                elif tag_entry['Key'] == 'Service':
                    tag_service = tag_entry['Value']
                else:
                    continue
            eip_tags = [tag_project, tag_app, tag_service]
            if ipaddress.IPv4Address(public_ip) in ipaddress.IPv4Network('13.0.0.0/8'):
                print('This ip is an squid IP, no action required')
            elif eip_tags not in tag_repo.Repos:
                print('Tag doesn\'t match tag tree, and add default Tags')
                client.create_tags(Resources=eip_ids, Tags=tag_repo.tag_default)
            else:
                print('Tag matches tag tree and already in there')
        else:
            print('No tags here, add default tags')
            client.create_tags(Resources=eip_ids, Tags=tag_repo.tag_default)

def tagging_natgw(region, account):
    natgwinfo = client.describe_nat_gateways()
    print(natgwinfo)
    natgw_num = len(natgwinfo['NatGateways'])
    # print(natgwinfo['natgw'])
    for i in range(natgw_num):
        natgw_ids = []
        tag_number = len(natgwinfo['NatGateways'][i]['Tags'])
        natgw_ids.append(natgwinfo['NatGateways'][i]['NatGatewayId'])
        print(natgw_ids)
        # print(natgw_ids)
        # print(type(natgw_ids))
        # print('natgw ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = natgwinfo['NatGateways'][i]['Tags'][j]
            # print(natgwinfo['natgw'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        natgw_tags = [tag_project, tag_app, tag_service]
        if natgw_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=natgw_ids, Tags=tag_repo.tag_default)
        else:
            print('Tag matches tag tree and already in there')

# tagging_natgw('ap-southeast-1', 'yding')
def tagging_network_acl(region, account):
    network_aclinfo = client.describe_network_acls()
    print(network_aclinfo)
    network_acl_num = len(network_aclinfo['NetworkAcls'])
    # print(network_aclinfo['network_acl'])
    for i in range(network_acl_num):
        network_acl_ids = []
        tag_number = len(network_aclinfo['NetworkAcls'][i]['Tags'])
        network_acl_ids.append(network_aclinfo['NetworkAcls'][i]['NetworkAclId'])
        print(network_acl_ids)
        # print(network_acl_ids)
        # print(type(network_acl_ids))
        # print('network_acl ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = network_aclinfo['NetworkAcls'][i]['Tags'][j]
            # print(network_aclinfo['network_acl'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        network_acl_tags = [tag_project, tag_app, tag_service]
        if network_acl_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=network_acl_ids, Tags=tag_repo.tag_default)
            print('Tags are not in tag trees so add default tags')
        else:
            print('Tag matches tag tree and already in there')

# tagging_network_acl('ap-southeast-1')

def tagging_routetables(region, account):
    routetableinfo = client.describe_route_tables()
    print(routetableinfo)
    routetable_num = len(routetableinfo['RouteTables'])
    # print(routetableinfo['routetables'])
    for i in range(routetable_num):
        routetable_ids = []
        tag_number = len(routetableinfo['RouteTables'][i]['Tags'])
        routetable_ids.append(routetableinfo['RouteTables'][i]['RouteTableId'])
        print(routetable_ids)
        # print(routetable_ids)
        # print(type(routetable_ids))
        # print('routetable ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = routetableinfo['RouteTables'][i]['Tags'][j]
            # print(routetableinfo['routetables'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        routetable_tags = [tag_project, tag_app, tag_service]
        if routetable_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=routetable_ids, Tags=tag_repo.tag_default)
            print(routetable_tags)
            print('Tag doesn\'t match tag tree so let\'s add default tags')
        else:
            print(routetable_tags)
            print('Tag matches tag tree and already in there')

def tagging_tgw(region, account):
    tgwinfo = client.describe_transit_gateways()
    print(tgwinfo)
    tgw_num = len(tgwinfo['TransitGateways'])
    # print(tgwinfo['tgw'])
    for i in range(tgw_num):
        tgw_owner = tgwinfo['TransitGateways'][i]['OwnerId']
        account_id = tag_repo.account_dictionary[account]
        # print(type(account_id))
        if tgw_owner != account_id:
            # print(type(tag_repo.account_dictionary[account]))
            print('this tgw does not belong to this account')
            continue
        else:
            print('this tgw belongs to this account')
            tgw_ids = []
            tag_number = len(tgwinfo['TransitGateways'][i]['Tags'])
            tgw_ids.append(tgwinfo['TransitGateways'][i]['TransitGatewayId'])
            # print(tgw_ids)
            # print(tgw_ids)
            # print(type(tgw_ids))
            # print('tgw ' + str(i) + ' has ' + str(tag_number) + ' tags')
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(tag_number):
                tag_entry = tgwinfo['TransitGateways'][i]['Tags'][j]
                # print(tgwinfo['tgw'][i]['Tags'][j])
                if tag_entry['Key'] == 'Project':
                    tag_project = tag_entry['Value']
                elif tag_entry['Key'] == 'App':
                    tag_app = tag_entry['Value']
                elif tag_entry['Key'] == 'Service':
                    tag_service = tag_entry['Value']
                else:
                    continue
            tgw_tags = [tag_project, tag_app, tag_service]
            if tgw_tags not in tag_repo.Repos:
                # print('Tag doesn\'t match tag tree')
                client.create_tags(Resources=tgw_ids, Tags=tag_repo.tag_default)
            else:
                print('Tag matches tag tree and already in there')

# tagging_vgw('ap-southeast-1', 'yding')
def tagging_tgw_attachment(region, account):
    tgw_attachmentinfo = client.describe_transit_gateway_attachments()
    print(tgw_attachmentinfo)
    tgw_attachment_num = len(tgw_attachmentinfo['TransitGatewayAttachments'])
    # print(tgw_attachmentinfo['tgw_attachment'])
    for i in range(tgw_attachment_num):
        tgw_attachment_ids = []
        tag_number = len(tgw_attachmentinfo['TransitGatewayAttachments'][i]['Tags'])
        tgw_attachment_ids.append(tgw_attachmentinfo['TransitGatewayAttachments'][i]['TransitGatewayAttachmentId'])
        print(tgw_attachment_ids)
        # print(tgw_attachment_ids)
        # print(type(tgw_attachment_ids))
        # print('tgw_attachment ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = tgw_attachmentinfo['TransitGatewayAttachments'][i]['Tags'][j]
            # print(tgw_attachmentinfo['tgw_attachment'][i]['Tags'][j])
            if tag_entry['Key'] == 'Project':
                tag_project = tag_entry['Value']
            elif tag_entry['Key'] == 'App':
                tag_app = tag_entry['Value']
            elif tag_entry['Key'] == 'Service':
                tag_service = tag_entry['Value']
            else:
                continue
        tgw_attachment_tags = [tag_project, tag_app, tag_service]
        if tgw_attachment_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            client.create_tags(Resources=tgw_attachment_ids, Tags=tag_repo.tag_default)
        else:
            print('Tag matches tag tree and already in there')

# tagging_tgw_attachment('ap-southeast-1')
def tagging_certificate(region, account):
    certificateinfo = certificate_client.list_certificates()
    certificate_num = len(certificateinfo['CertificateSummaryList'])
    print(certificate_num)
    # certificatetags = certificate_client.list_tags_for_certificate()
    # print(certificateinfo)
    # print(certificatetags)
    # certificate_num = len(certificateinfo['CertificateSummaryList'])
    for i in range(certificate_num):
        certificate_arn = certificateinfo['CertificateSummaryList'][i]['CertificateArn']
        # print(certificate_arn)
        tag_number = len(certificate_client.list_tags_for_certificate(CertificateArn=certificate_arn)['Tags'])
        # print(certificate_arn)
        # print('certificate ' + str(i) + ' has ' + str(tag_number) + ' tags')
        tag_project = ''
        tag_app = ''
        tag_service = ''
        for j in range(tag_number):
            tag_entry = certificate_client.list_tags_for_certificate(CertificateArn=certificate_arn)['Tags']
            print(tag_entry[j])
            # print(certificateinfo['CertificateSummaryList'][i]['Tags'][j])
            if tag_entry[j]['Key'] == 'Project':
                tag_project = tag_entry[j]['Value']
            elif tag_entry[j]['Key'] == 'App':
                tag_app = tag_entry[j]['Value']
            elif tag_entry[j]['Key'] == 'Service':
                tag_service = tag_entry[j]['Value']
            else:
                continue
        certificate_tags = [tag_project, tag_app, tag_service]
        print(certificate_tags)
        if certificate_tags not in tag_repo.Repos:
            # print('Tag doesn\'t match tag tree')
            certificate_client.add_tags_to_certificate(CertificateArn=certificate_arn, Tags=tag_repo.tag_default)
            print('Add default tags')
        else:
            print('Tag matches tag tree and already in there')

# tagging_certificate('ap-southeast-1')
def tagging_dxconns(region, account):
    dxconninfo = dx_client.describe_connections()
    print(dxconninfo)
    dxconn_num = len(dxconninfo['connections'])
    if dxconn_num == 0:
        print('there is no dxconn in this acount and region')
    else:
        for i in range(dxconn_num):
            dxconn_id = []
            dxconn_id = dxconninfo['connections'][i]['connectionId']
            dxconn_account_id = tag_repo.account_dictionary[account]
            arn = 'arn:aws:directconnect:{regionname}:{id}:dxcon/{connectionid}'.format(regionname = region, id = dxconn_account_id, connectionid = dxconn_id)
            # print(arn)
            dxconn_tag_num = len(dxconninfo['connections'][i]['tags'])
            print(dxconn_tag_num)
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(dxconn_tag_num):
            # tag_entry = dxconn_client.describe_tags(resourceArns=[arn])
            # print(tag_entry)
                dxconn_tag_entry = dxconninfo['connections'][i]['tags'][j]
                if dxconn_tag_entry['key'] == 'Project':
                    tag_project = dxconn_tag_entry['value']
                elif dxconn_tag_entry['key'] == 'App':
                    tag_app = dxconn_tag_entry['value']
                elif dxconn_tag_entry['key'] == 'Service':
                    tag_service = dxconn_tag_entry['value']
                else:
                    continue
            dxconn_tags = [tag_project, tag_app, tag_service]
            print(dxconn_tags)
            if dxconn_tags not in tag_repo.Repos:
                print('Tag doesn\'t match tag tree')
                dx_client.tag_resource(resourceArn=arn, tags=tag_repo.dx_tag_default)
                print('Add default tags')
            else:
                print('Tag matches tag tree and already in there')

# tagging_dxconns('ap-southeast-1', 'network-pre-prd')
def tagging_dxvif(region, account):
    dxvifinfo = dx_client.describe_virtual_interfaces()
    print(dxvifinfo)
    dxvif_num = len(dxvifinfo['virtualInterfaces'])
    if dxvif_num == 0:
        print('there is no dxvif in this acount and region')
    else:
        for i in range(dxvif_num):
            dxvif_id = []
            dxvif_id = dxvifinfo['virtualInterfaces'][i]['virtualInterfaceId']
            dxvif_account_id = tag_repo.account_dictionary[account]
            arn = 'arn:aws:directconnect:{regionname}:{id}:dxvif/{connectionid}'.format(regionname = region, id = dxvif_account_id, connectionid = dxvif_id)
            # print(arn)
            dxvif_tag_num = len(dxvifinfo['virtualInterfaces'][i]['tags'])
            print(dxvif_tag_num)
            tag_project = ''
            tag_app = ''
            tag_service = ''
            for j in range(dxvif_tag_num):
            # tag_entry = dxvif_client.describe_tags(resourceArns=[arn])
            # print(tag_entry)
                dxvif_tag_entry = dxvifinfo['virtualInterfaces'][i]['tags'][j]
                if dxvif_tag_entry['key'] == 'Project':
                    tag_project = dxvif_tag_entry['value']
                elif dxvif_tag_entry['key'] == 'App':
                    tag_app = dxvif_tag_entry['value']
                elif dxvif_tag_entry['key'] == 'Service':
                    tag_service = dxvif_tag_entry['value']
                else:
                    continue
            dxvif_tags = [tag_project, tag_app, tag_service]
            print(dxvif_tags)
            if dxvif_tags not in tag_repo.Repos:
                print('Tag doesn\'t match tag tree')
                dx_client.tag_resource(resourceArn=arn, tags=tag_repo.dx_tag_default)
                print('Add default tags')
            else:
                print('Tag matches tag tree and already in there')

# tagging_dxvif('us-east-1', 'network-pre-prd')
