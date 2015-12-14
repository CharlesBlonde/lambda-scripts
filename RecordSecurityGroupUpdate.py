import json
import boto3
import datetime
import time
import sys

sgId = 'sg-XXXXXXXX'

'''
return diff between two arrays
'''


def diff(a, b):
    b = set(b)
    return [aa for aa in a if aa not in b]


def find_added_rules(event):
    rulesAdded = []
    for record in event['Records']:
        if record['EventSource'] == 'aws:sns':
            #print(record['Sns']['Message'])
            snsMessage = json.loads(record['Sns']['Message'])
            if 'configurationItem' in snsMessage and snsMessage['configurationItem']['resourceType'] == 'AWS::EC2::SecurityGroup' and \
                            snsMessage['configurationItem']['resourceId'] == sgId:
                changedProperties = snsMessage['configurationItemDiff']['changedProperties']
                createChanges = [change for change in changedProperties.keys() if
                                 changedProperties[change]['changeType'] == 'CREATE']
                for createChange in createChanges:
                    ipProtocol = changedProperties[createChange]['updatedValue']['ipProtocol']
                    fromPort = changedProperties[createChange]['updatedValue']['fromPort']
                    toPort = changedProperties[createChange]['updatedValue']['toPort']
                    deleteChanges = [delete for delete in changedProperties.keys() if
                                     changedProperties[delete]['changeType'] == 'DELETE'
                                     and ipProtocol == changedProperties[delete]['previousValue']['ipProtocol']
                                     and fromPort == changedProperties[delete]['previousValue']['fromPort']
                                     and toPort == changedProperties[delete]['previousValue']['toPort']]

                    # There already exist a rule for this ports/protocol.Check if new IP range(s) has been added
                    if (deleteChanges):
                        for deleteChange in deleteChanges:
                            addedIpRanges = diff(changedProperties[createChange]['updatedValue']['ipRanges'],
                                                 changedProperties[deleteChange]['previousValue']['ipRanges'])
                            if addedIpRanges:
                                ipRangesAdded = {
                                    "MessageId": record['Sns']['MessageId'] + ":" + ipProtocol + ":" + str(
                                        fromPort) + ":" + str(toPort),
                                    "IpProtocol": ipProtocol,
                                    "FromPort": fromPort,
                                    "ToPort": toPort,
                                    "AddedIpRanges": addedIpRanges,
                                    "RawMessage": snsMessage,
                                    "CreateAt": int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
                                }
                                rulesAdded.append(ipRangesAdded)
                    else:
                        # New ports/protocol rule
                        ipRangesAdded = {
                            "MessageId": record['Sns']['MessageId'] + ":" + ipProtocol + ":" + str(
                                fromPort) + ":" + str(toPort),
                            "IpProtocol": ipProtocol,
                            "FromPort": fromPort,
                            "ToPort": toPort,
                            "AddedIpRanges": changedProperties[createChange]['updatedValue']['ipRanges'],
                            "RawMessage": snsMessage,
                            "CreateAt": int(time.mktime(datetime.datetime.now().timetuple()) * 1000)
                        }
                        rulesAdded.append(ipRangesAdded)

    return rulesAdded


def lambda_handler(event, context):
    try:
        rulesAdded = find_added_rules(event)
        if rulesAdded:
            dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
            table = dynamodb.Table('update_openvpn_security_group_log')
            for rule in rulesAdded:
                table.put_item(Item=rule)
    except:
        print("Received event: " + json.dumps(event, indent=2))
        print "Unexpected error:", sys.exc_info()[0]
        raise
