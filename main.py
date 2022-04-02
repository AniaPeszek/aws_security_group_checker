import csv
import boto3
from os.path import exists


def read_regions():
    regions = [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]
    return regions


def describe_security_group(region):
    ec2 = boto3.client('ec2', region_name=region)
    return ec2.describe_security_groups()['SecurityGroups']


def is_port_in_scope(ip_permission, port):
    if not ip_permission.get('FromPort'):
        return True
    else:
        from_port = ip_permission['FromPort']
        to_port = ip_permission['ToPort']
        return from_port <= port <= to_port


def is_ip_in_ip_ranges(ip_permission):
    if len(ip_permission['IpRanges']) == 0:
        return False
    else:
        for ip_range in ip_permission['IpRanges']:
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
    return False


def check_security_groups(port, protocol, path_to_file, is_new_file=False):
    """Function to check if SecurityGroups in each region don't allow inbound traffic from ip range 0.0.0.0/0
    on specific port for given protocol. SGs which break rules are saved in .csv file.

    Args:
        port (int): The port number
        protocol (str): protocol name, for all use '-1'
        path_to_file (str): Result location, .csv file is saved
        is_new_file (bool): A flag used to choose if you want to create new file (True)
            or add record to existing file (False)
            (default is False)

    Returns:
        None
    """

    if is_new_file:
        if not exists(path_to_file):
            create_basic_csv_file(path_to_file)
        else:
            print('This file exists and sth important can be inside... '
                  'Instead of deleting everything new records will be added...')

    regions = read_regions()
    for region in regions:
        security_groups_list = describe_security_group(region)
        for group in security_groups_list:
            for ip_permission in group['IpPermissions']:
                if ip_permission['IpProtocol'] == '-1' or protocol in ip_permission['IpProtocol']:
                    if is_port_in_scope(ip_permission, port):
                        if is_ip_in_ip_ranges(ip_permission):
                            sg_id = group['GroupId']
                            sg_name = group['GroupName']
                            aws_account_id = group['OwnerId']
                            with open(path_to_file, 'a+', encoding='UTF8', newline='') as f:
                                writer = csv.writer(f)
                                writer.writerow([sg_id, sg_name, region, aws_account_id])
                            break
    print(f"SecurityGroups checking is finished. You can find your results in {path_to_file}")
    return


def create_basic_csv_file(path_to_file):
    columns = ['SG_ID', 'SG_NAME', 'AWS_REGION', 'AWS_ACCOUNT_ID']
    with open(path_to_file, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(columns)


if __name__ == '__main__':
    # where do you want to save results?
    path_to_results = 'results/unsafe_sg-v1.csv'

    check_security_groups(port=22, protocol='tcp', path_to_file=path_to_results, is_new_file=True)
