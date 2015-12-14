import unittest
import json

import RecordSecurityGroupUpdate

class TestRecordSecurityGroupUpdateTestCase(unittest.TestCase):
    def test_diff(self):
        diff = RecordSecurityGroupUpdate.diff(['a', 'b', 'c', 'd'], ['a', 'b'])
        self.assertEqual(diff, ['c', 'd'])

    def test_find_added_rule(self):
        jsonString = """{"Records": [
 {
 "EventVersion": "1.0",
 "EventSubscriptionArn": "arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",
 "EventSource": "aws:sns",
 "Sns": {
 "SignatureVersion": "1",
 "Timestamp": "2015-12-12T11:25:14.833Z",
 "Signature": "NwAH00NrdoEdFRgJZFVgughpvfCdf+QYiCP8P7XgMqhjg9SDqrejNBQb0oybNAS8J1rmG1XJcO3A9QITf3Xy3/a+c3p6WNpyMSdBSAZ/Nane/v1jKqUuYTK5C0whzi6E/hVp0HIqDCmNKK3+SVsPhReeEU1e8y0aD+/zhlalLytnMLpPgjRtPVrGskTj2dvIrImNUntu9x6j2loIei7m2fLjNKAFPq78+yaMBVqXteeJerXyMboO+PZ/0iuzmjMiSk4ocDQQ1AdQW+cy3WB2m2MqfzJu4HRecoZBljDK/CtpyrvqwqpE60iyJMQHbqhpVNDkahcXKBFd50rDu34o5Q==",
 "SigningCertUrl": "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-bb750dd426d95ee9390147a5624348ee.pem",
 "MessageId": "9107adab-5d6f-57a9-acda-e34d5b35860a",
 "Message": "{\\"configurationItemDiff\\":{\\"changedProperties\\":{\\"Configuration.IpPermissions.1\\":{\\"previousValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"82.124.18.7/32\\",\\"85.169.125.166/32\\",\\"37.160.139.201/32\\",\\"37.162.153.98/32\\",\\"80.215.225.175/32\\",\\"80.215.228.176/32\\",\\"203.218.43.29/32\\",\\"37.165.120.151/32\\",\\"86.249.20.49/32\\",\\"37.164.65.156/32\\",\\"14.136.149.30/32\\",\\"89.92.57.89/32\\",\\"88.168.48.15/32\\",\\"81.249.13.101/32\\",\\"81.249.76.125/32\\",\\"82.124.214.73/32\\",\\"82.124.132.235/32\\",\\"80.215.173.237/32\\",\\"203.218.213.139/32\\",\\"90.62.15.85/32\\",\\"90.35.67.214/32\\",\\"86.249.230.197/32\\",\\"176.182.109.199/32\\"],\\"prefixListIds\\":[]},\\"updatedValue\\":null,\\"changeType\\":\\"DELETE\\"},\\"Configuration.IpPermissions.2\\":{\\"previousValue\\":null,\\"updatedValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"176.182.109.199/32\\",\\"86.249.230.197/32\\",\\"219.77.82.69/32\\"],\\"prefixListIds\\":[]},\\"changeType\\":\\"CREATE\\"},\\"Configuration.IpPermissions.0\\":{\\"previousValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":22,\\"toPort\\":22,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"128.79.12.97/32\\",\\"171.18.11.249/32\\",\\"89.92.78.204/32\\"],\\"prefixListIds\\":[]},\\"updatedValue\\":null,\\"changeType\\":\\"DELETE\\"}},\\"changeType\\":\\"UPDATE\\"},\\"configurationItem\\":{\\"configurationItemVersion\\":\\"1.1\\",\\"configurationItemCaptureTime\\":\\"2015-12-12T11:25:13.166Z\\",\\"configurationStateId\\":667,\\"relatedEvents\\":[\\"0dbb8ff1-408f-4a2d-8417-ecc99460308b\\"],\\"awsAccountId\\":\\"999888444333\\",\\"configurationItemStatus\\":\\"OK\\",\\"resourceId\\":\\"sg-XXXXXXXX\\",\\"resourceName\\":null,\\"ARN\\":\\"arn:aws:ec2:eu-west-1:999888444333:security-group/sg-XXXXXXXX\\",\\"awsRegion\\":\\"eu-west-1\\",\\"availabilityZone\\":\\"Not Applicable\\",\\"configurationStateMd5Hash\\":\\"e90b08b209ea26e5db5bb8f472a17730\\",\\"resourceType\\":\\"AWS::EC2::SecurityGroup\\",\\"resourceCreationTime\\":null,\\"tags\\":{\\"Name\\":\\"openvpn\\"},\\"relationships\\":[{\\"resourceId\\":\\"eni-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::NetworkInterface\\",\\"name\\":\\"Is associated with NetworkInterface\\"},{\\"resourceId\\":\\"i-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::Instance\\",\\"name\\":\\"Is associated with Instance\\"},{\\"resourceId\\":\\"vpc-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::VPC\\",\\"name\\":\\"Is contained in Vpc\\"}],\\"configuration\\":{\\"ownerId\\":\\"999888444333\\",\\"groupName\\":\\"OpenVPN\\",\\"groupId\\":\\"sg-XXXXXXXX\\",\\"description\\":\\"OpenVPN\\",\\"ipPermissions\\":[{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"176.182.109.199/32\\",\\"86.249.230.197/32\\",\\"219.77.82.69/32\\"],\\"prefixListIds\\":[]}],\\"ipPermissionsEgress\\":[{\\"ipProtocol\\":\\"-1\\",\\"fromPort\\":null,\\"toPort\\":null,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]},{\\"ipProtocol\\":\\"udp\\",\\"fromPort\\":1194,\\"toPort\\":1194,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]},{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":1194,\\"toPort\\":1194,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]}],\\"vpcId\\":\\"vpc-XXXXXXXX\\",\\"tags\\":[{\\"key\\":\\"Name\\",\\"value\\":\\"openvpn\\"}]}},\\"notificationCreationTime\\":\\"2015-12-12T11:25:13.981Z\\",\\"messageType\\":\\"ConfigurationItemChangeNotification\\",\\"recordVersion\\":\\"1.2\\"}",
 "MessageAttributes": {},
 "Type": "Notification",
 "UnsubscribeUrl": "https://sns.eu-west-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",
 "TopicArn": "arn:aws:sns:eu-west-1:999888444333:config-topic",
 "Subject": "[AWS Config:eu-west-1] AWS::EC2::SecurityGroup sg-XXXXXXXX Updated in Account 999888444333"
 }
 }
 ]
}"""
        jsonEvent = json.loads(jsonString)
        addedRules = RecordSecurityGroupUpdate.find_added_rules(jsonEvent)
        self.assertEqual(len(addedRules), 1)
        self.assertEqual(addedRules[0]['MessageId'], '9107adab-5d6f-57a9-acda-e34d5b35860a:tcp:3389:3389')
        self.assertEqual(addedRules[0]['IpProtocol'], 'tcp')
        self.assertEqual(addedRules[0]['ToPort'], 3389)
        self.assertEqual(addedRules[0]['FromPort'], 3389)
        self.assertEqual(addedRules[0]['AddedIpRanges'], ['219.77.82.69/32'])
        self.assertTrue(addedRules[0]['RawMessage'])
        self.assertTrue(addedRules[0]['CreateAt'])

    def test_should_find_added_rule(self):
        jsonString = """{"Records": [
 {
 "EventVersion": "1.0",
 "EventSubscriptionArn": "arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",
 "EventSource": "aws:sns",
 "Sns": {
 "SignatureVersion": "1",
 "Timestamp": "2015-12-12T11:25:14.833Z",
 "Signature": "NwAH00NrdoEdFRgJZFVgughpvfCdf+QYiCP8P7XgMqhjg9SDqrejNBQb0oybNAS8J1rmG1XJcO3A9QITf3Xy3/a+c3p6WNpyMSdBSAZ/Nane/v1jKqUuYTK5C0whzi6E/hVp0HIqDCmNKK3+SVsPhReeEU1e8y0aD+/zhlalLytnMLpPgjRtPVrGskTj2dvIrImNUntu9x6j2loIei7m2fLjNKAFPq78+yaMBVqXteeJerXyMboO+PZ/0iuzmjMiSk4ocDQQ1AdQW+cy3WB2m2MqfzJu4HRecoZBljDK/CtpyrvqwqpE60iyJMQHbqhpVNDkahcXKBFd50rDu34o5Q==",
 "SigningCertUrl": "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-bb750dd426d95ee9390147a5624348ee.pem",
 "MessageId": "9107adab-5d6f-57a9-acda-e34d5b35860a",
 "Message": "{\\"configurationItemDiff\\":{\\"changedProperties\\":{\\"Configuration.IpPermissions.5\\": {\\"changeType\\": \\"CREATE\\", \\"previousValue\\": null, \\"updatedValue\\": {\\"fromPort\\": 25, \\"ipProtocol\\": \\"tcp\\", \\"ipRanges\\": [\\"176.182.109.199/32\\"], \\"prefixListIds\\": [], \\"toPort\\": 25, \\"userIdGroupPairs\\": []}},\\"Configuration.IpPermissions.1\\":{\\"previousValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"82.124.18.7/32\\",\\"85.169.125.166/32\\",\\"37.160.139.201/32\\",\\"37.162.153.98/32\\",\\"80.215.225.175/32\\",\\"80.215.228.176/32\\",\\"203.218.43.29/32\\",\\"37.165.120.151/32\\",\\"86.249.20.49/32\\",\\"37.164.65.156/32\\",\\"14.136.149.30/32\\",\\"89.92.57.89/32\\",\\"88.168.48.15/32\\",\\"81.249.13.101/32\\",\\"81.249.76.125/32\\",\\"82.124.214.73/32\\",\\"82.124.132.235/32\\",\\"80.215.173.237/32\\",\\"203.218.213.139/32\\",\\"90.62.15.85/32\\",\\"90.35.67.214/32\\",\\"86.249.230.197/32\\",\\"176.182.109.199/32\\"],\\"prefixListIds\\":[]},\\"updatedValue\\":null,\\"changeType\\":\\"DELETE\\"},\\"Configuration.IpPermissions.2\\":{\\"previousValue\\":null,\\"updatedValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"176.182.109.199/32\\",\\"86.249.230.197/32\\",\\"219.77.82.69/32\\"],\\"prefixListIds\\":[]},\\"changeType\\":\\"CREATE\\"},\\"Configuration.IpPermissions.0\\":{\\"previousValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":22,\\"toPort\\":22,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"128.79.12.97/32\\",\\"171.18.11.249/32\\",\\"89.92.78.204/32\\"],\\"prefixListIds\\":[]},\\"updatedValue\\":null,\\"changeType\\":\\"DELETE\\"}},\\"changeType\\":\\"UPDATE\\"},\\"configurationItem\\":{\\"configurationItemVersion\\":\\"1.1\\",\\"configurationItemCaptureTime\\":\\"2015-12-12T11:25:13.166Z\\",\\"configurationStateId\\":667,\\"relatedEvents\\":[\\"0dbb8ff1-408f-4a2d-8417-ecc99460308b\\"],\\"awsAccountId\\":\\"999888444333\\",\\"configurationItemStatus\\":\\"OK\\",\\"resourceId\\":\\"sg-XXXXXXXX\\",\\"resourceName\\":null,\\"ARN\\":\\"arn:aws:ec2:eu-west-1:999888444333:security-group/sg-XXXXXXXX\\",\\"awsRegion\\":\\"eu-west-1\\",\\"availabilityZone\\":\\"Not Applicable\\",\\"configurationStateMd5Hash\\":\\"e90b08b209ea26e5db5bb8f472a17730\\",\\"resourceType\\":\\"AWS::EC2::SecurityGroup\\",\\"resourceCreationTime\\":null,\\"tags\\":{\\"Name\\":\\"openvpn\\"},\\"relationships\\":[{\\"resourceId\\":\\"eni-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::NetworkInterface\\",\\"name\\":\\"Is associated with NetworkInterface\\"},{\\"resourceId\\":\\"i-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::Instance\\",\\"name\\":\\"Is associated with Instance\\"},{\\"resourceId\\":\\"vpc-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::VPC\\",\\"name\\":\\"Is contained in Vpc\\"}],\\"configuration\\":{\\"ownerId\\":\\"999888444333\\",\\"groupName\\":\\"OpenVPN\\",\\"groupId\\":\\"sg-XXXXXXXX\\",\\"description\\":\\"OpenVPN\\",\\"ipPermissions\\":[{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"176.182.109.199/32\\",\\"86.249.230.197/32\\",\\"219.77.82.69/32\\"],\\"prefixListIds\\":[]}],\\"ipPermissionsEgress\\":[{\\"ipProtocol\\":\\"-1\\",\\"fromPort\\":null,\\"toPort\\":null,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]},{\\"ipProtocol\\":\\"udp\\",\\"fromPort\\":1194,\\"toPort\\":1194,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]},{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":1194,\\"toPort\\":1194,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]}],\\"vpcId\\":\\"vpc-XXXXXXXX\\",\\"tags\\":[{\\"key\\":\\"Name\\",\\"value\\":\\"openvpn\\"}]}},\\"notificationCreationTime\\":\\"2015-12-12T11:25:13.981Z\\",\\"messageType\\":\\"ConfigurationItemChangeNotification\\",\\"recordVersion\\":\\"1.2\\"}",
 "MessageAttributes": {},
 "Type": "Notification",
 "UnsubscribeUrl": "https://sns.eu-west-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",
 "TopicArn": "arn:aws:sns:eu-west-1:999888444333:config-topic",
 "Subject": "[AWS Config:eu-west-1] AWS::EC2::SecurityGroup sg-XXXXXXXX Updated in Account 999888444333"
 }
 }
 ]
}"""
        jsonEvent = json.loads(jsonString)
        addedRules = RecordSecurityGroupUpdate.find_added_rules(jsonEvent)
        self.assertEqual(len(addedRules), 2)
        self.assertEqual(addedRules[0]['MessageId'], '9107adab-5d6f-57a9-acda-e34d5b35860a:tcp:3389:3389')
        self.assertEqual(addedRules[0]['IpProtocol'], 'tcp')
        self.assertEqual(addedRules[0]['ToPort'], 3389)
        self.assertEqual(addedRules[0]['FromPort'], 3389)
        self.assertEqual(addedRules[0]['AddedIpRanges'], ['219.77.82.69/32'])
        self.assertTrue(addedRules[0]['RawMessage'])
        self.assertTrue(addedRules[0]['CreateAt'])

        self.assertEqual(addedRules[1]['MessageId'], '9107adab-5d6f-57a9-acda-e34d5b35860a:tcp:25:25')
        self.assertEqual(addedRules[1]['IpProtocol'], 'tcp')
        self.assertEqual(addedRules[1]['ToPort'], 25)
        self.assertEqual(addedRules[1]['FromPort'], 25)
        self.assertEqual(addedRules[1]['AddedIpRanges'], ['176.182.109.199/32'])
        self.assertTrue(addedRules[1]['RawMessage'])
        self.assertTrue(addedRules[1]['CreateAt'])

    def test_should_find_rules_added_return_empty_if_no_added(self):
        jsonString = """{"Records": [ 
 { 
 "EventVersion": "1.0",  
 "EventSubscriptionArn": "arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",  
 "EventSource": "aws:sns",  
 "Sns": { 
 "SignatureVersion": "1",  
 "Timestamp": "2015-12-12T11:25:14.833Z",  
 "Signature": "NwAH00NrdoEdFRgJZFVgughpvfCdf+QYiCP8P7XgMqhjg9SDqrejNBQb0oybNAS8J1rmG1XJcO3A9QITf3Xy3/a+c3p6WNpyMSdBSAZ/Nane/v1jKqUuYTK5C0whzi6E/hVp0HIqDCmNKK3+SVsPhReeEU1e8y0aD+/zhlalLytnMLpPgjRtPVrGskTj2dvIrImNUntu9x6j2loIei7m2fLjNKAFPq78+yaMBVqXteeJerXyMboO+PZ/0iuzmjMiSk4ocDQQ1AdQW+cy3WB2m2MqfzJu4HRecoZBljDK/CtpyrvqwqpE60iyJMQHbqhpVNDkahcXKBFd50rDu34o5Q==",  
 "SigningCertUrl": "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-bb750dd426d95ee9390147a5624348ee.pem",  
 "MessageId": "9107adab-5d6f-57a9-acda-e34d5b35860a",  
 "Message": "{\\"configurationItemDiff\\":{\\"changedProperties\\":{\\"Configuration.IpPermissions.1\\":{\\"previousValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"82.124.18.7/32\\",\\"85.169.125.166/32\\",\\"37.160.139.201/32\\",\\"37.162.153.98/32\\",\\"80.215.225.175/32\\",\\"80.215.228.176/32\\",\\"203.218.43.29/32\\",\\"37.165.120.151/32\\",\\"86.249.20.49/32\\",\\"37.164.65.156/32\\",\\"14.136.149.30/32\\",\\"89.92.57.89/32\\",\\"88.168.48.15/32\\",\\"81.249.13.101/32\\",\\"81.249.76.125/32\\",\\"82.124.214.73/32\\",\\"82.124.132.235/32\\",\\"219.77.82.69/32\\",\\"80.215.173.237/32\\",\\"203.218.213.139/32\\",\\"90.62.15.85/32\\",\\"90.35.67.214/32\\",\\"86.249.230.197/32\\",\\"176.182.109.199/32\\"],\\"prefixListIds\\":[]},\\"updatedValue\\":null,\\"changeType\\":\\"DELETE\\"},\\"Configuration.IpPermissions.2\\":{\\"previousValue\\":null,\\"updatedValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"176.182.109.199/32\\",\\"86.249.230.197/32\\",\\"219.77.82.69/32\\"],\\"prefixListIds\\":[]},\\"changeType\\":\\"CREATE\\"},\\"Configuration.IpPermissions.0\\":{\\"previousValue\\":{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":22,\\"toPort\\":22,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"128.79.12.97/32\\",\\"171.18.11.249/32\\",\\"89.92.78.204/32\\"],\\"prefixListIds\\":[]},\\"updatedValue\\":null,\\"changeType\\":\\"DELETE\\"}},\\"changeType\\":\\"UPDATE\\"},\\"configurationItem\\":{\\"configurationItemVersion\\":\\"1.1\\",\\"configurationItemCaptureTime\\":\\"2015-12-12T11:25:13.166Z\\",\\"configurationStateId\\":667,\\"relatedEvents\\":[\\"0dbb8ff1-408f-4a2d-8417-ecc99460308b\\"],\\"awsAccountId\\":\\"999888444333\\",\\"configurationItemStatus\\":\\"OK\\",\\"resourceId\\":\\"sg-XXXXXXXX\\",\\"resourceName\\":null,\\"ARN\\":\\"arn:aws:ec2:eu-west-1:999888444333:security-group/sg-XXXXXXXX\\",\\"awsRegion\\":\\"eu-west-1\\",\\"availabilityZone\\":\\"Not Applicable\\",\\"configurationStateMd5Hash\\":\\"e90b08b209ea26e5db5bb8f472a17730\\",\\"resourceType\\":\\"AWS::EC2::SecurityGroup\\",\\"resourceCreationTime\\":null,\\"tags\\":{\\"Name\\":\\"openvpn\\"},\\"relationships\\":[{\\"resourceId\\":\\"eni-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::NetworkInterface\\",\\"name\\":\\"Is associated with NetworkInterface\\"},{\\"resourceId\\":\\"i-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::Instance\\",\\"name\\":\\"Is associated with Instance\\"},{\\"resourceId\\":\\"vpc-XXXXXXXX\\",\\"resourceName\\":null,\\"resourceType\\":\\"AWS::EC2::VPC\\",\\"name\\":\\"Is contained in Vpc\\"}],\\"configuration\\":{\\"ownerId\\":\\"999888444333\\",\\"groupName\\":\\"OpenVPN\\",\\"groupId\\":\\"sg-XXXXXXXX\\",\\"description\\":\\"OpenVPN\\",\\"ipPermissions\\":[{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":3389,\\"toPort\\":3389,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"176.182.109.199/32\\",\\"86.249.230.197/32\\",\\"219.77.82.69/32\\"],\\"prefixListIds\\":[]}],\\"ipPermissionsEgress\\":[{\\"ipProtocol\\":\\"-1\\",\\"fromPort\\":null,\\"toPort\\":null,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]},{\\"ipProtocol\\":\\"udp\\",\\"fromPort\\":1194,\\"toPort\\":1194,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]},{\\"ipProtocol\\":\\"tcp\\",\\"fromPort\\":1194,\\"toPort\\":1194,\\"userIdGroupPairs\\":[],\\"ipRanges\\":[\\"0.0.0.0/0\\"],\\"prefixListIds\\":[]}],\\"vpcId\\":\\"vpc-XXXXXXXX\\",\\"tags\\":[{\\"key\\":\\"Name\\",\\"value\\":\\"openvpn\\"}]}},\\"notificationCreationTime\\":\\"2015-12-12T11:25:13.981Z\\",\\"messageType\\":\\"ConfigurationItemChangeNotification\\",\\"recordVersion\\":\\"1.2\\"}",  
 "MessageAttributes": {},  
 "Type": "Notification",  
 "UnsubscribeUrl": "https://sns.eu-west-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",  
 "TopicArn": "arn:aws:sns:eu-west-1:999888444333:config-topic",  
 "Subject": "[AWS Config:eu-west-1] AWS::EC2::SecurityGroup sg-XXXXXXXX Updated in Account 999888444333" 
 } 
 } 
 ] 
}"""
        jsonEvent = json.loads(jsonString)
        addedRules = RecordSecurityGroupUpdate.find_added_rules(jsonEvent)
        self.assertEqual(len(addedRules), 0)
    
    def test_should_not_failt_if_no_security_group_event(self):
        jsonString = """{
 "Records": [
 {
 "EventVersion": "1.0",
 "EventSubscriptionArn": "arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",
 "EventSource": "aws:sns",
 "Sns": {
 "SignatureVersion": "1",
 "Timestamp": "2015-12-12T20:17:54.082Z",
 "Signature": "CS4ROrSRrwuFkrCIrAm9OtYcz/lfRc5O6R91jkdhdiT6x0YI/2E+IXlQQNcVhkIsqRc5rarbz0rGNmGihf0dQSaZKxkWliOAzuumeYbJ/nSeXrlXsJ1W/oaEZkiyb4YqDfZhTw4ONB7MVpuCdxH5O6PkTLRqDadMTyJr8HdIo/InkUcQ15OLV4TumrDJDbWynFyzoBPCum6FRphVvu9t7xuWldgWSCoWIYJmclwGFd+fU/0xSfYc3G/vflSX74YyZukwXogUtPRP7SBEdqI2zSO0FSYPSBxQrQW2lQ9CpRVCNYHalwsb4BeaX41F6Y4Uxum0UKPN19pt4nX+/JpYyw==",
 "SigningCertUrl": "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-bb750dd426d95ee9390147a5624348ee.pem",
 "MessageId": "34986e86-8f9c-5ce0-9467-20600caeec45",
 "Message": "{\\"StatusCode\\":\\"Failed\\",\\"Service\\":\\"AWS Auto Scaling\\",\\"AutoScalingGroupName\\":\\"my-first-asg\\",\\"Description\\":\\"Launching a new EC2 instance. Status Reason: Not authorized for images: [ami-69ae251e]. Launching EC2 instance failed.\\",\\"ActivityId\\":\\"42fe8a28-01b1-43d2-96cf-d756ac135680\\",\\"Event\\":\\"autoscaling:EC2_INSTANCE_LAUNCH_ERROR\\",\\"Details\\":{\\"Availability Zone\\":\\"eu-west-1a\\",\\"Subnet ID\\":\\"subnet-c39053b4\\"},\\"AutoScalingGroupARN\\":\\"arn:aws:autoscaling:eu-west-1:999888444333:autoScalingGroup:d31a5d5f-19fc-4855-a4b3-5c98c9d82190:autoScalingGroupName/my-first-asg\\",\\"Progress\\":100,\\"Time\\":\\"2015-12-12T20:17:54.012Z\\",\\"AccountId\\":\\"999888444333\\",\\"RequestId\\":\\"42fe8a28-01b1-43d2-96cf-d756ac135680\\",\\"StatusMessage\\":\\"Not authorized for images: [ami-69ae251e]. Launching EC2 instance failed.\\",\\"EndTime\\":\\"2015-12-12T20:17:53.000Z\\",\\"EC2InstanceId\\":\\"\\",\\"StartTime\\":\\"2015-12-12T20:17:53.853Z\\",\\"Cause\\":\\"At 2015-12-12T20:17:53Z an instance was started in response to a difference between desired and actual capacity, increasing the capacity from 0 to 1.\\"}",
 "MessageAttributes": {},
 "Type": "Notification",
 "UnsubscribeUrl": "https://sns.eu-west-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:eu-west-1:999888444333:config-topic:d3092599-ece3-47c0-b9c1-f8db44855039",
 "TopicArn": "arn:aws:sns:eu-west-1:999888444333:config-topic",
 "Subject": "Auto Scaling: failed launch for group \\"my-first-asg\\""
 }
 }
 ]
}"""
        jsonEvent = json.loads(jsonString)
        addedRules = RecordSecurityGroupUpdate.find_added_rules(jsonEvent)
        self.assertEqual(len(addedRules), 0)


if __name__ == '__main__':
    unittest.main()
