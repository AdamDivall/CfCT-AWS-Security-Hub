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
    pcidss_enabled=event['PCIDSSEnabled']
    member_session=assume_role(account_id, role_to_assume)
    member_client=member_session.client('securityhub', region_name=region, config=config)
    if pcidss_enabled == 'Yes':
        if region != ct_home_region:
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.IAM.1',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.IAM.1 - IAM root user access key should not exist' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.IAM.2',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.IAM.2 - IAM users should not have IAM policies attached' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.IAM.3',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.IAM.3 - IAM policies should not allow full '*' administrative privileges' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.IAM.4',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.IAM.4 - Hardware MFA should be enabled for the root user' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.IAM.5',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.IAM.5 - Virtual MFA should be enabled for the root user' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.IAM.6',
                ControlStatus='DISABLED',
                DisabledReason=f'This check is for a global resource and already enabled in {ct_home_region}. Enabling this global resource in multiple regions is repetitive and not required.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.IAM.6 - MFA should be enabled for all IAM users' in Region {region}.")
            member_client.update_standards_control(
                StandardsControlArn=f'arn:aws:securityhub:{region}:{account_id}:control/pci-dss/v/3.2.1/PCI.Config.1',
                ControlStatus='DISABLED',
                DisabledReason=f'Disabled recording of global resources in all regions other than {ct_home_region}. This rule requires recording of global resources in order to pass.'
            )
            print(f"Disabled Payment Card Industry Data Security Standard Control: 'PCI.Config.1 - AWS Config should be enabled' in Region {region}.")                                                                        
    else:
        print(f"Payment Card Industry Data Security Standard is not enabled in Account ID: {account_id} in Region {region}")

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