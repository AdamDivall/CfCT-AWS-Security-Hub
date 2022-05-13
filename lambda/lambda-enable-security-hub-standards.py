import boto3
import os
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
    role_to_assume=event['RoleToAssume']
    member_session=assume_role(account_id, role_to_assume)
    member_client=member_session.client('securityhub', region_name=region, config=config)
    aws_foundations_arn=(f"arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0")
    aws_foundations_subscription_arn=(f"arn:aws:securityhub:{region}:{account_id}:subscription/aws-foundational-security-best-practices/v/1.0.0")
    cis_foundations_arn=("arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0")
    cis_foundations_subscription_arn=(f"arn:aws:securityhub:{region}:{account_id}:subscription/cis-aws-foundations-benchmark/v/1.2.0")
    pcidss_arn=(f"arn:aws:securityhub:{region}::standards/pci-dss/v/3.2.1")
    pcidss_subscription_arn=(f"arn:aws:securityhub:{region}:{account_id}:subscription/pci-dss/v/3.2.1")
    if os.environ['AWS_FOUNDATIONS'] == 'Yes':
        try:
            member_client.batch_enable_standards(
                StandardsSubscriptionRequests=[
                    {
                        'StandardsArn': aws_foundations_arn
                    }
                ]
            )
            print(f"Enabled AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}.")
        except Exception as e:
            print(f"Failed to enable AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}. Error: {e}.")
    else:
        try:
            member_client.batch_disable_standards(
                StandardsSubscriptionArns=[
                    aws_foundations_subscription_arn
                ]
            )
            print(f"Disabled AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}.")
        except Exception as e:
            print(f"Failed to disable AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}. Error: {e}.")
    if os.environ['CIS_FOUNDATIONS'] == 'Yes':
        try:
            member_client.batch_enable_standards(
                StandardsSubscriptionRequests=[
                    {
                        'StandardsArn': cis_foundations_arn
                    }
                ]
            )
            print(f"Enabled CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}.")
        except Exception as e:
            print(f"Failed to enable CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}. Error: {e}.")
    else:
        try:
            member_client.batch_disable_standards(
                StandardsSubscriptionArns=[
                    cis_foundations_subscription_arn
                ]
            )
            print(f"Disabled CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}.")
        except Exception as e:
            print(f"Failed to disable CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}. Error: {e}.")
    if os.environ['PCIDSS'] == 'Yes':
        try:
            member_client.batch_enable_standards(
                StandardsSubscriptionRequests=[
                    {
                        'StandardsArn': pcidss_arn
                    }
                ]
            )
            print(f"Enabled PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}.")
        except Exception as e:
            print(f"Failed to enable PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}. Error: {e}.")
    else:
        try:
            member_client.batch_disable_standards(
                StandardsSubscriptionArns=[
                    pcidss_subscription_arn
                ]
            )
            print(f"Disabled PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}.")
        except Exception as e:
            print(f"Failed to disable PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}. Error: {e}.")
    event["AWSFoundationEnabled"]=os.environ['AWS_FOUNDATIONS']
    event["CISFoundationEnabled"]=os.environ['CIS_FOUNDATIONS']
    event["PCIDSSEnabled"]=os.environ['PCIDSS']
    return event

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