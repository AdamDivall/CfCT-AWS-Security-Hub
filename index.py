import boto3
import os
import cfnresponse
from botocore.exceptions import ClientError

security_hub_master_account_id=os.environ['SECURITY_HUB_MASTER_ACCOUNT_ID']
role_to_assume=os.environ['ROLE_TO_ASSUME']

def lambda_handler(event, context):
    security_hub_regions=boto3.Session().get_available_regions('securityhub')
    control_tower_regions=get_control_tower_regions()
    security_hub_master_account_session=assume_role(security_hub_master_account_id, role_to_assume)
    accounts=get_all_accounts()
    if 'RequestType' in event:    
        if (event['RequestType'] == 'Create' or event['RequestType'] == 'Update'):
            try:
                for region in control_tower_regions:
                    if region in security_hub_regions:
                        enable_security_hub_master(security_hub_master_account_session, region)
                        enable_security_hub_member(security_hub_master_account_session, region, accounts)
            except ClientError as e: 
                print(e.response['Error']['Message']) 
                cfnresponse.send(event, context, cfnresponse.FAILED, e.response)

        elif (event['RequestType'] == 'Delete'):
            try:
                for region in control_tower_regions:
                    if region in security_hub_regions:
                        disable_security_hub(security_hub_master_account_session, region, accounts)
            except ClientError as e: 
                print(e.response['Error']['Message']) 
                cfnresponse.send(event, context, cfnresponse.FAILED, e.response)

        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
    else:
        for region in control_tower_regions:
            if region in security_hub_regions:
                enable_security_hub_master(security_hub_master_account_session, region)
                enable_security_hub_member(security_hub_master_account_session, region, accounts)     

def get_control_tower_regions():
    """
    Description:
        Finds the AWS Control Tower governed regions by Identifying the AWS Regions used within the AWS CloudFormation StackSets deployed by AWS Control Tower.
    Returns:
        List of AWS Control Tower governed regions.
    """
    
    cloudformation_client=boto3.client('cloudformation')
    control_tower_regions=set()
    try:
        stack_instances=cloudformation_client.list_stack_instances(
            StackSetName="AWSControlTowerBP-BASELINE-CONFIG"
        )
        for stack in stack_instances['Summaries']:
            control_tower_regions.add(stack['Region'])
    except Exception as e:
        print(f"Control Tower StackSet not found in this region")
        control_tower_regions = {'us-east-1', 'eu-west-2'}
    print(f"Control Tower Regions: {list(control_tower_regions)}")
    return list(control_tower_regions)

def assume_role(aws_account_id, role_to_assume):
    """
    Description:
        Assumes the provided role in the specified AWS Account and returns a GuardDuty Client.
    Parameters:
        "aws_account_id" = AWS Account Number.
        "role_to_assume" = Role to assume in target account.
    Returns:
        Security Hub Client in the specified AWS Account and AWS Region.
    """

    # Beginning the AssumeRole process for the Account.
    sts_client=boto3.client('sts')
    response=sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{aws_account_id}:role/{role_to_assume}',
        RoleSessionName='EnableSecurityHub'
    )
    # Storing STS Credentials.
    sts_session=boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    print(f"Assumed session for Account ID: {aws_account_id}.")
    return sts_session

def get_all_accounts():
    """
    Description:
        Get all Accounts within the AWS Organization.
    Returns:
        A list of all AWS Accounts in the AWS Organization that have a Status of 'ACTIVE'.
    """

    org_client=boto3.client('organizations')
    all_accounts=[]
    active_accounts=[]
    token_tracker={}
    while True:
        member_accounts=org_client.list_accounts(
            **token_tracker
        )
        all_accounts.extend(member_accounts['Accounts'])
        if 'NextToken' in member_accounts:
            token_tracker['NextToken'] = member_accounts['NextToken']
        else:
            break
    for account in all_accounts:
        if account['Status'] == 'ACTIVE':
            active_accounts.append(account)
    return active_accounts

def enable_security_hub_master(security_hub_master_account_session, region):
    cloudtrail_client=boto3.client('cloudtrail')
    cloudtrail_response=cloudtrail_client.describe_trails(
        trailNameList=[
            'aws-controltower-BaselineCloudTrail',
        ]
    )
    control_tower_home_region=cloudtrail_response['trailList'][0]['HomeRegion']
    sh_client=boto3.client('securityhub', region_name=region)
    delegated_admin_client=security_hub_master_account_session.client('securityhub', region_name=region)
    delegated_admin_account=sh_client.list_organization_admin_accounts()
    try:
        delegated_admin_client.get_findings()
    except Exception:
        print(f"Security Hub is not enabled in Account ID: {security_hub_master_account_id} in region {region}.")
    try:
        delegated_admin_client.enable_security_hub(
            EnableDefaultStandards=False
        )
    except Exception:
        print(f"Security Hub is enabled in in Account ID: {security_hub_master_account_id} in region {region}.")
    try:
        if delegated_admin_account['AdminAccounts'] == security_hub_master_account_id:
            print(f"Account ID: {security_hub_master_account_id} is the Delegated Admin for Security Hub.")
        else:
            print(f"Delegating Admin for Security Hub to Account ID: {security_hub_master_account_id}.")
            sh_client.enable_organization_admin_account(
                AdminAccountId=security_hub_master_account_id
            )
    except Exception:
        print(f"Delegated Admin has already been configured for Security Hub in region {region}.")
    delegated_admin_client.update_organization_configuration(
        AutoEnable=True
    )
    process_security_standards(delegated_admin_client, region, security_hub_master_account_id)

def enable_security_hub_member(security_hub_master_account_session, region, accounts):
    delegated_admin_client=security_hub_master_account_session.client('securityhub', region_name=region)
    for account in accounts:
        if account['Id'] != security_hub_master_account_id:
            member_session=assume_role(account['Id'], role_to_assume)
            member_client=member_session.client('securityhub', region_name=region)
            try:
                member_client.enable_security_hub(
                    EnableDefaultStandards=False
                )
            except Exception:
                print(f"Security Hub is enabled in Account ID: {account['Id']} in region {region}.")
            try:
                delegated_admin_client.create_members(
                    AccountDetails=[
                        {
                            'AccountId': account['Id'],
                            'Email': account['Email']
                        }
                    ]
                )
            except Exception:
                print(f"Account ID: {account['Id']} is already associated with Security Hub Admin Account.")
            process_security_standards(member_client, region, account['Id'])

def process_security_standards(member_client, region, account_id):
    aws_foundations_arn=(f"arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0")
    aws_foundations_subscription_arn=(f"arn:aws:securityhub:{region}:{account_id}:subscription/aws-foundational-security-best-practices/v/1.0.0")
    cis_foundations_arn=("arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0")
    cis_foundations_subscription_arn=(f"arn:aws:securityhub:{region}:{account_id}:subscription/cis-aws-foundations-benchmark/v/1.2.0")
    pcidss_arn=(f"arn:aws:securityhub:{region}::standards/pci-dss/v/3.2.1")
    pcidss_subscription_arn=(f"arn:aws:securityhub:{region}:{account_id}:subscription/pci-dss/v/3.2.1")
    aws_foundations_enabled=False
    cis_foundations_enabled=False
    pcidss_enabled=False
    enabled_standards=member_client.get_enabled_standards()
    for item in enabled_standards["StandardsSubscriptions"]:
        if aws_foundations_arn in item["StandardsArn"]:
            aws_foundations_enabled = True
        if cis_foundations_arn in item["StandardsArn"]:
            cis_foundations_enabled = True
        if pcidss_arn in item["StandardsArn"]:
            pcidss_enabled = True
    if os.environ['AWS_FOUNDATIONS'] == 'Yes':
        if aws_foundations_enabled:
            print(f"AWS Foundational Security Best Practices v1.0.0 Security Standard is already enabled in Account ID: {account_id} in {region}.")
        else:
            try:
                member_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[
                        {
                            'StandardsArn': aws_foundations_arn
                        }
                    ])
                print(f"Enabled AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}.")
            except Exception as e:
                print(f"Failed to enable AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}.")
    # Disable AWS Standard
    else:
        if not aws_foundations_enabled:
            print(f"AWS Foundational Security Best Practices v1.0.0 Security Standard is already disabled in Account ID: {account_id} in {region}.")
        else:
            try:
                member_client.batch_disable_standards(
                    StandardsSubscriptionArns=[
                        aws_foundations_subscription_arn
                    ]
                )
                print(f"Disabled AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}.")
            except Exception as e:
                print(f"Failed to disable AWS Foundational Security Best Practices v1.0.0 Security Standard in Account ID: {account_id} in {region}.")
    if os.environ['CIS_FOUNDATIONS'] == 'Yes':
        if cis_foundations_enabled:
            print(f"CIS AWS Foundations Benchmark v1.2.0 Security Standard is already enabled in Account ID: {account_id} in {region}.")
        else:
            try:
                member_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[
                        {
                            'StandardsArn': cis_foundations_arn
                        }
                    ])
                print(f"Enabled CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}.")
            except Exception as e:
                print(f"Failed to enable CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}.")
    # Disable AWS Standard
    else:
        if not cis_foundations_enabled:
            print(f"CIS AWS Foundations Benchmark v1.2.0 Security Standard is already disabled in Account ID: {account_id} in {region}.")
        else:
            try:
                member_client.batch_disable_standards(
                    StandardsSubscriptionArns=[
                        cis_foundations_subscription_arn
                    ]
                )
                print(f"Disabled CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}.")
            except Exception as e:
                print(f"Failed to disable CIS AWS Foundations Benchmark v1.2.0 Security Standard in Account ID: {account_id} in {region}.")
    if os.environ['PCIDSS'] == 'Yes':
        if pcidss_enabled:
            print(f"PCI DSS v3.2.1 Security Standard is already enabled in Account ID: {account_id} in {region}.")
        else:
            try:
                member_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[
                        {
                            'StandardsArn': pcidss_arn
                        }
                    ])
                print(f"Enabled PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}.")
            except Exception as e:
                print(f"Failed to enable PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}.")
    # Disable AWS Standard
    else:
        if not pcidss_enabled:
            print(f"PCI DSS v3.2.1 Security Standard is already disabled in Account ID: {account_id} in {region}.")
        else:
            try:
                member_client.batch_disable_standards(
                    StandardsSubscriptionArns=[
                        pcidss_subscription_arn
                    ]
                )
                print(f"Disabled PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}.")
            except Exception as e:
                print(f"Failed to disable PCI DSS v3.2.1 Security Standard in Account ID: {account_id} in {region}.")

def disable_security_hub(security_hub_master_account_session, region, accounts):
    sh_client=boto3.client('securityhub', region_name=region)
    try:
        sh_client.disable_organization_admin_account(
            AdminAccountId=security_hub_master_account_id
        )
        print(f"Disabled Delegated Admin for Security Hub in Account ID: {security_hub_master_account_id}.")
    except Exception:
        print(f"Delegated Admin is not configured.")
    delegated_admin_client=security_hub_master_account_session.client('securityhub', region_name=region)
    member_accounts=[]
    for account in accounts:
        if account['Id'] != security_hub_master_account_id:        
            member_session=assume_role(account['Id'], role_to_assume)
            member_client=member_session.client('securityhub', region_name=region)
            member_accounts.append(account['Id'])
            try:
                member_client.disable_security_hub()
            except Exception:
                print(f"Failed to disable AWS Security Hub in Account ID: {account['Id']} in region {region}.")
    delegated_admin_client.disassociate_members(AccountIds=member_accounts)
    print(f"Disassociated Member Accounts from the Security Hub Admin Account in {region}.")
    delegated_admin_client.delete_members(AccountIds=member_accounts)
    print(f"Deleted Member Accounts from the Security Hub Admin Account in {region}.")
    try:
        delegated_admin_client.disable_security_hub()
        print(f"Disabled Security Hub in the Security Hub Admin Account in {region}.")
    except Exception:
        print(f"Security Hub is already Disabled in the Security Hub Admin Account in {region}.")
