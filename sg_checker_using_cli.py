import subprocess
import json
import csv
from os.path import exists
from main import is_port_in_scope, is_ip_in_ip_ranges, create_basic_csv_file


def read_regions_using_cli():
    regions = subprocess.run(
        ["aws", "ec2", "describe-regions", "--query", 'Regions[].{Name:RegionName}', "--output", "text"],
        stdout=subprocess.PIPE,
        universal_newlines=True).stdout.splitlines()
    return regions


def describe_security_group_using_cli(region):
    description = subprocess.check_output(
        ["aws", "ec2", "describe-security-groups", "--region", region, "--output", "json"], universal_newlines=True)
    return json.loads(description)


def check_security_groups_using_cli(port, protocol, path_to_file, is_new_file=False):
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

    regions = read_regions_using_cli()
    for region in regions:
        security_groups_list = describe_security_group_using_cli(region)['SecurityGroups']
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


if __name__ == '__main__':
    # where do you want to save results?
    path_to_results = 'results/unsafe_sg-v0csv'

    check_security_groups_using_cli(port=22, protocol='tcp', path_to_file=path_to_results, is_new_file=True)
