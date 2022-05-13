import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

config=Config(
    retries={
        'max_attempts':10,
        'mode':'adaptive'
    }
)

def lambda_handler(event, context):
    region=event['Region']
    account_id=event['AccountId']
    ct_home_region=event['ControlTowerHomeRegion']
    role_to_assume=event['RoleToAssume']
    aws_foundations_enabled=event['AWSFoundationEnabled']
    member_session=assume_role(account_id, role_to_assume)
    member_client=member_session.client('securityhub', region_name=region, config=config)
    if aws_foundations_enabled == 'Yes':
        if region != ct_home_region:
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.1',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.1 - IAM policies should not allow full '*' administrative privileges' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.2',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.2 - IAM users should not have IAM policies attached' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.3',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.3 - IAM users' access keys should be rotated every 90 days or less' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.4',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.4 - IAM root user access key should not exist' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.5',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.5 - MFA should be enabled for all IAM users that have a console password' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.6',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.6 - Hardware MFA should be enabled for the root user' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.7',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.7 - Password policies for IAM users should have strong configurations' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.8',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.8 - Unused IAM user credentials should be removed' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/IAM.21',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'IAM.21 - IAM customer managed policies that you create should not allow wildcard actions for services' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/aws-foundational-security-best-practices/v/1.0.0/Config.1',
                ControlStatus='DISABLED',
                DisabledReason=f'Disabled recording of global resources in all regions other than {ct_home_region}. This rule requires recording of global resources in order to pass.'
            )
            print(f"Disabled AWS Foundational Best Practices Control: 'Config.1 - AWS Config should be enabled' in Region {region}.")
    else:
        print(f"AWS Foundational Best Practises is not enabled in Account ID: {account_id} in Region {region}")

def assume_role(aws_account_id, role_to_assume):
    sts_client=boto3.client('sts')
    response=sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{aws_account_id}:role/{role_to_assume}',
        RoleSessionName='EnableSecurityHub'
    )
    sts_session=boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    print(f"Assumed session for Account ID: {aws_account_id}.")
    return sts_session