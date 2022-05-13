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
    log_archive_account_id=event['LogArchiveAccountId']
    region=event['Region']
    account_id=event['AccountId']
    ct_home_region=event['ControlTowerHomeRegion']
    role_to_assume=event['RoleToAssume']
    cis_foundations_enabled=event['CISFoundationEnabled']
    member_session=assume_role(account_id, role_to_assume)
    member_client=member_session.client('securityhub', region_name=region, config=config)
    if cis_foundations_enabled == 'Yes':
        if region != ct_home_region:
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.2',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.2 - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.3',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.3 - Ensure credentials unused for 90 days or greater are disabled' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.4',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.4 - Ensure access keys are rotated every 90 days or less' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.5',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.5 - Ensure IAM password policy requires at least one uppercase letter' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.6',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.6 - Ensure IAM password policy requires at least one lowercase letter' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.7',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.7 - Ensure IAM password policy requires at least one symbol' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.8',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.8 - Ensure IAM password policy requires at least one number' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.9',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.9 - Ensure IAM password policy requires a minimum length of 14 or greater' in Region {region}.")                        
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.10',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.10 - Ensure IAM password policy prevents password reuse' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.11',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.11 - Ensure IAM password policy expires passwords within 90 days or less' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.12',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.12 - Ensure no root account access key exists' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.13',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.13 - Ensure MFA is enabled for the 'root' account' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.14',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.14 - Ensure hardware MFA is enabled for the 'root' account' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.16',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.16 - Ensure IAM policies are attached only to groups or roles' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.20',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.20 - Ensure a support role has been created to manage incidents with AWS Support' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.22',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '1.22 - Ensure IAM policies that allow full '*:*' administrative privileges are not created' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/2.5',
                ControlStatus='DISABLED',
                DisabledReason=f'Disabled recording of global resources in all regions other than {ct_home_region}. This rule requires recording of global resources in order to pass.'
            )
            print(f"Disabled CIS AWS Foundations Benchmark Control: '2.5 - Ensure AWS Config is enabled' in Region {region}.")
            if account_id == log_archive_account_id:
                member_client.update_standards_control(
                    StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/2.7',
                    ControlStatus='DISABLED',
                    DisabledReason=f'Disabled recording of global resources in all regions other than {ct_home_region}. This rule requires recording of global resources in order to pass.'
                )
                print(f"Disabled CIS AWS Foundations Benchmark Control: '2.7 - Ensure CloudTrail logs are encrypted at rest using AWS KMS keys' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/1.1',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '1.1 - Avoid the use of the 'root' account' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.1',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.1 - Ensure a log metric filter and alarm exist for unauthorized API calls' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.2',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.2 - Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA' in Region {region}.")    
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.3',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.3 - Ensure a log metric filter and alarm exist for usage of 'root' account' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.4',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.4 - Ensure a log metric filter and alarm exist for IAM policy changes' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.5',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.5 - Ensure a log metric filter and alarm exist for CloudTrail configuration changes' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.6',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.6 - Ensure a log metric filter and alarm exist for AWS Management Console authentication failures' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.7',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.7 - Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.8',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.8 - Ensure a log metric filter and alarm exist for S3 bucket policy changes' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.9',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.9 - Ensure a log metric filter and alarm exist for AWS Config configuration changes' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.10',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.10 - Ensure a log metric filter and alarm exist for security group changes' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.11',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.11 - Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.12',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.12 - Ensure a log metric filter and alarm exist for changes to network gateways' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.13',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.13 - Ensure a log metric filter and alarm exist for route table changes' in Region {region}.")
        member_client.update_standards_control(
            StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/cis-aws-foundations-benchmark/v/1.2.0/3.14',
            ControlStatus='DISABLED',
            DisabledReason=f'Amazon GuardDuty is being used for anomaly detection instead of CloudWatch alarms, which can be noisy.'
        )
        print(f"Disabled CIS AWS Foundations Benchmark Control: '3.14 - Ensure a log metric filter and alarm exist for VPC changes' in Region {region}.")
    else:
        print(f"CIS AWS Foundations Benchmark Control is not enabled in Account ID: {account_id} in Region {region}")
        
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