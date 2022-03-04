import boto3
import os
import json
import cfnresponse
from botocore.config import Config
from botocore.exceptions import ClientError

security_hub_master_account_id=os.environ['SECURITY_HUB_MASTER_ACCOUNT_ID']
security_hub_state_machine_arn=os.environ['SECURITY_HUB_STATE_MACHINE_ARN']
log_archive_account_id=os.environ['LOG_ARCHIVE_ACCOUNT_ID']
role_to_assume=os.environ['ROLE_TO_ASSUME']
config=Config(
    retries={
        'max_attempts':10,
        'mode':'adaptive'
    }
)
stepfunction_client = boto3.client('stepfunctions')

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
                        ct_home_region=enable_security_hub_master(security_hub_master_account_session, region)
                        enable_security_hub_member(security_hub_master_account_session, region, accounts, ct_home_region)
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
                ct_home_region=enable_security_hub_master(security_hub_master_account_session, region)
                enable_security_hub_member(security_hub_master_account_session, region, accounts, ct_home_region)     

def get_control_tower_regions():
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

def get_all_accounts():
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
    ct_home_region=cloudtrail_client.describe_trails(
        trailNameList=[
            'aws-controltower-BaselineCloudTrail',
        ]
    )['trailList'][0]['HomeRegion']
    sh_client=boto3.client('securityhub', region_name=region, config=config)
    config_client=security_hub_master_account_session.client('config', region_name=region)
    delegated_admin_client=security_hub_master_account_session.client('securityhub', region_name=region, config=config)
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
    if region == ct_home_region:
        finding_aggregators=delegated_admin_client.list_finding_aggregators()['FindingAggregators']
        if len(finding_aggregators) > 0:
            print(f"Security Hub already has a Findings Aggregator in Account ID: {security_hub_master_account_id}.")
        else:
            if region == ct_home_region:
                delegated_admin_client.create_finding_aggregator(
                    RegionLinkingMode='ALL_REGIONS'
                )
                print(f"Security Hub Findings Aggregator created in Account ID: {security_hub_master_account_id}.")
            else:
                print(f"Current Region {region} is not the Control Tower Home Region.")
    else:
        config_recorder=config_client.describe_configuration_recorders()
        try:
            config_client.put_configuration_recorder(
                ConfigurationRecorder={
                    'name': config_recorder['ConfigurationRecorders'][0]['name'],
                    'roleARN': config_recorder['ConfigurationRecorders'][0]['roleARN'],
                    'recordingGroup': {
                        'allSupported': True,
                        'includeGlobalResourceTypes': False 
                    }
                }
            )
            print(f"Excluded Global Resources from AWS Config in Region {region} in Account ID: {security_hub_master_account_id}.")
        except Exception as e:
            print(f"AWS Config is not Enable in Account ID: {security_hub_master_account_id} in Region: {region}.")
    return ct_home_region

def enable_security_hub_member(security_hub_master_account_session, region, accounts, ct_home_region):
    delegated_admin_client=security_hub_master_account_session.client('securityhub', region_name=region, config=config)
    for account in accounts:
        member_session=assume_role(account['Id'], role_to_assume)
        member_client=member_session.client('securityhub', region_name=region, config=config)
        if account['Id'] != security_hub_master_account_id:
            try:
                member_client.enable_security_hub(
                    EnableDefaultStandards=False
                )
                print(f"Enabled Security Hub in Account ID: {account['Id']} in Region {region}.")
            except Exception:
                print(f"Security Hub is already enabled in Account ID: {account['Id']} in Region {region}.")
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
            if region != ct_home_region:
                try:
                    config_client=member_session.client('config', region_name=region)
                    config_recorder=config_client.describe_configuration_recorders()
                    config_client.put_configuration_recorder(
                        ConfigurationRecorder={
                            'name': config_recorder['ConfigurationRecorders'][0]['name'],
                            'roleARN': config_recorder['ConfigurationRecorders'][0]['roleARN'],
                            'recordingGroup': {
                                'allSupported': True,
                                'includeGlobalResourceTypes': False 
                            }
                        }
                    )
                    print(f"Excluded Global Resources from AWS Config in Region {region} in Account ID: {account['Id']}.")
                except Exception as e:
                    print(f"AWS Config is not Enable in Account ID: {account['Id']} in Region: {region}.")
        security_hub_state_machine_input={
            "SecurityHubMasterAccountId":security_hub_master_account_id,
            "LogArchiveAccountId":log_archive_account_id,
            "Region":region,
            "ControlTowerHomeRegion":ct_home_region,
            "AccountId":account['Id'],
            "RoleToAssume":role_to_assume
        }
        try:
            stepfunction_client.start_execution(
                stateMachineArn=security_hub_state_machine_arn,
                input=json.dumps(security_hub_state_machine_input)
            )
        except Exception as e:
            print(f"Unable to Trigger Enabling of Security Hub in Account ID: {account['Id']} in Region {region}. Error: {e}.")

def disable_security_hub(security_hub_master_account_session, region, accounts):
    sh_client=boto3.client('securityhub', region_name=region, config=config)
    try:
        sh_client.disable_organization_admin_account(
            AdminAccountId=security_hub_master_account_id
        )
        print(f"Disabled Delegated Admin for Security Hub in Account ID: {security_hub_master_account_id}.")
    except Exception:
        print(f"Delegated Admin is not configured.")
    delegated_admin_client=security_hub_master_account_session.client('securityhub', region_name=region, config=config)
    member_accounts=[]
    for account in accounts:
        if account['Id'] != security_hub_master_account_id:        
            member_session=assume_role(account['Id'], role_to_assume)
            member_client=member_session.client('securityhub', region_name=region, config=config)
            member_accounts.append(account['Id'])
            try:
                member_client.disable_security_hub()
                print(f"Disabled Security Hub in Account ID: {account['Id']} in Region {region}.")
            except Exception:
                print(f"Failed to disable Security Hub in Account ID: {account['Id']} in region {region}.")
    delegated_admin_client.disassociate_members(AccountIds=member_accounts)
    print(f"Disassociated Member Accounts from the Security Hub Admin Account in {region}.")
    delegated_admin_client.delete_members(AccountIds=member_accounts)
    print(f"Deleted Member Accounts from the Security Hub Admin Account in {region}.")
    try:
        delegated_admin_client.disable_security_hub()
        print(f"Disabled Security Hub in the Security Hub Admin Account in {region}.")
    except Exception:
        print(f"Security Hub is already Disabled in the Security Hub Admin Account in {region}.")
