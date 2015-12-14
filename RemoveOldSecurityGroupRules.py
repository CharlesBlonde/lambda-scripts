from __future__ import print_function  # Python 2/3 compatibility
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import datetime
import time

DRYRUN = False
SECURITY_GROUP_ID = 'sg-XXXXXXXX'

dateChange = int((time.mktime(datetime.datetime.now().timetuple()) * 1000) - (1000 * 60 * 60 * 10))

def lambda_handler(event, context):
    print("Running")
    dynamodb = boto3.resource('dynamodb')
    ec2 = boto3.client('ec2')
    table = dynamodb.Table('update_openvpn_security_group_log')
    responses = table.scan(FilterExpression=Attr('DeleteAt').not_exists() & Attr('CreateAt').lt(dateChange))

    for item in responses['Items']:
        for ipRange in item['AddedIpRanges']:
            IpPermissions = {
                "IpProtocol": item['IpProtocol'],
                "FromPort": int(item['FromPort']),
                "ToPort": int(item['ToPort']),
                "IpRanges": [{"CidrIp": ipRange}]
            }

            try:
                print("Removing: "+str(IpPermissions))
                ec2.revoke_security_group_ingress(DryRun=DRYRUN,
                                                  GroupId=SECURITY_GROUP_ID,
                                                  IpPermissions=[IpPermissions]
                                                  )
            except ClientError as e:
                print(e)

            item['DeleteAt'] = int((time.mktime(datetime.datetime.now().timetuple()) * 1000))
            table.put_item(Item=item)

if __name__ == "__main__":
    lambda_handler(None, None)