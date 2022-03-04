# AWS Security Hub

The CloudFormation Template and Lambda Function have been adapted from the original source on [GitHub](https://raw.githubusercontent.com/aws-samples/aws-control-tower-securityhub-enabler/main/aws-control-tower-securityhub-enabler.template) and the associated [blog post](https://aws.amazon.com/blogs/mt/automating-aws-security-hub-alerts-with-aws-control-tower-lifecycle-events/).

The reason I've adapted it is that I noticed a few things:
1.  Once deployed, it enables Security Hub in every AWS Region across all AWS Accounts in the Organisation.  
    * From my perspective, that could potentially add additional costs to the overarching bill.
    * There maybe situations where Clients restrict the AWS Regions that can be used within AWS e.g. through Service Control Policies. 
    * Control Tower may not have all AWS Regions governed by Control Tower meaning that effectively other AWS Best Practices may not be configured within those regions.
    * **Change Made:** The `get_control_tower_regions` python function has been created to identify the Control Tower governed regions by listing the regions utilised from a deployed CloudFormation StackSet `AWSControlTowerBP-BASELINE-CONFIG` which occurs on any Control Tower deployment.  This is in light of the fact that there is no API for Control Tower.  The lambda function logic has been adjusted to loop through all regions governed by Control Tower first and if this is a supported region by Security Hub to then proceed. 
    * **Change Made:** The `get_all_accounts` python function has been updated to only return AWS Accounts in the Organisation that have a status of 'ACTIVE'. Therefore any AWS Accounts that are in a suspended state pending deletion are ignored.
2.  Once deployed, Security Hub wasn't configured with a Delegated Admin or to auto-invite AWS Accounts within the Organisation.
    * **Change Made:** The `enable_security_hub_admin` python function has been updated to use the `enable_organization_admin_account` and `update_organization_configuration` boto3 API's to ensure that a Delegated Admin is configured and that Auto-Enable is also turned on.
3.  For each AWS Account Security Hub was enabled in every region and therefore there was duplication of some controls that ultimately increase the costs of running Security Hub and in turn AWS Config as well.  For example: IAM Controls only need to be checked in a Single Region per AWS Account therefore duplication of the Config Rule is providing no additional value.
    * **Change Made:** The `enable_security_hub_admin` python function has been updated to create a findings aggregator for all regions to send to the Control Tower Home Region.
    * **Change Made:** Both the `enable_security_hub_admin` and the `enable_security_hub_members` python functions have been updated to disable Config Global Recording for any region that isn't the Control Tower Home Region.
    * **Change Made:** The `Lambda-Security-Hub-Disable-AWS-Foundations-Global-Controls`, `Lambda-Security-Hub-Disable-CIS-Foundations-Global-Controls` and `Lambda-Security-Hub-Disable-PCIDSS-Global-Controls` Lambda Functions have been created to disable duplicated Global Controls as per the [Best Practices for cross-region aggregation of security findings in Security Hub](https://aws.amazon.com/blogs/security/best-practices-for-cross-region-aggregation-of-security-findings/). Specifically the controls that have been disabled are as per the documentation for each of the Security Standards [AWS Foundational Best Practices controls that you might want to disable](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-to-disable.html), [CIS AWS Foundations Benchmark controls that you might want to disable](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-cis-to-disable.html) and [PCI DSS controls that you might want to disable](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-pcidss-to-disable.html). Considering the issues of scaling I've leveraged Step Functions for the process of executing multiple accounts at the same time and the use of exponential backoff within the code to ensure that it doesn't run into API throttling issues.
4.  If you try to delete the AWS CloudFormation Stack that is created following on from the enabling of a Delegated Admin then it would fail to disable Security Hub.
    * **Change Made:** The `disable_security_hub` python function has been updated to loop through all Members and deregister the Delegated Admin and then loop through all Active AWS Accounts and disabling Security Hub in all configured regions.
5.  Added the Capabiity for both newly created AWS Accounts through the Account Vending Maching component of Control Tower or existing AWS Accounts that have been joined to the AWS Organization and registered in Control Tower to have Security Hub enabled.
    * **Change Made:** Update to the CloudFormation Template to create an EventBridge Rule that is triggered based on a Control Tower LifeCycle Event `CreateManagedAccount`.

## Architecture Overview

![alt](./diagrams/aws-securityhub.png)

## Pre-Requisites and Installation

### Pre-Requisites

There is an overarching assumption that you already have [Customisation for Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/) deployed within your Control Tower Environment.

1.  Clone the GitHub Repo to your local device.
2.  Create an S3 Bucket where you'll then upload the `securityhub.zip` file to. Make a note of the bucket name and the prefix to the `securityhub.zip`. Note: The region where you create the bucket will need to be in the region of the Control Tower home region since that is where the Lambda Function will be created.
3.  Create a prefix within the S3 Bucket named `lambda-layers` and upload both `cfnresponse.zip` and `boto3.zip` to that prefix.

### Installation

1.  Copy the CloudFormation Template `enable-securityhub.yaml` should be added to the `/templates` folder for use with Customisations for Control Tower.
2.  Copy the CloudFormation Parameters `enable-securityhub.json` should be added to `/parameters` folder for use with Customisations for Control Tower.
3.  Update the CloudFormation Parameters `enable-securityhub.json` with the required details:
    * **OrganizationId:** This is used to implement conditions within the IAM Policy used for the Lambda Execution Role. This can be obtained from with AWS Organisations.
    * **SecurityHubMasterAccountId:** This is the AWS Account ID of the Account that you wish to configure as the delegated admin for Security Hub.  It's recommended to use the Security Account (formerly called Audit Account) configured by Control Tower.
    * **LogArchiveAccountId:** This is the AWS Account ID of the Account that has been configured as the delegated admin for Security Hub.  It's recommended to use the Security Account (formerly called Audit Account) configured by Control Tower.
    * **S3SourceBucket:** This is the S3 Bucket where the Lambda Function source files are located. 
    * **S3Key:** This is the prefix within the S3 Bucket where the Lambda Function source files are located. 
    * **RoleToAssume:** This is used within the Lambda Function to AssumeRole into other AWS Accounts in order to Create/Configure/Delete different AWS Services such as Security Hub.  This is preconfigured with a default value of `AWSControlTowerExecution` since this IAM Role is created in all AWS Accounts as part the AWS Control Tower setup.
    * **EnableAWSFoundations:** This is used within the Lambda Function to specify whether or not the AWS Foundational Security Best Practices v1.0.0 Security Standard should be enabled or not. This is preconfigured to Yes to enable the standard. 
    * **EnableCISFoundations:** This is used within the Lambda Function to specify whether or not the CIS AWS Foundations Benchmark v1.2.0 Security Standard should be enabled or not. This is preconfigured to Yes to enable the standard.
    * **EnablePCIDSS:** This is used within the Lambda Function to specify whether or not the PCI DSS v3.2.1 Security Standard should be enabled or not. This is preconfigured to No to enable the standard.

    The above values should be configured within the `enable-securityhub.json`:

    ```json
    [
        {
            "ParameterKey": "OrganizationId",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "SecurityHubMasterAccountId",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "LogArchiveAccountId",
            "ParameterValue": ""
        },        
        {
            "ParameterKey": "S3SourceBucket",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "S3Key",
            "ParameterValue": ""
        },
        {
            "ParameterKey": "RoleToAssume",
            "ParameterValue": "AWSControlTowerExecution"
        },
        {
            "ParameterKey": "EnableAWSFoundations",
            "ParameterValue": "Yes"
        },  
        {
            "ParameterKey": "EnableCISFoundations",
            "ParameterValue": "Yes"
        },
        {
            "ParameterKey": "EnablePCIDSS",
            "ParameterValue": "No"
        }
    ]
    ```

4.  Update the `manifest.yaml` and configure the `deployment_targets` and `regions` accordingly based on your needs. The deployment target should be the AWS Control Tower Management Account since the Lambda Function that is invoked uses API Calls that are run are only available to the Master Account whilst the region should be configured to the Control Tower home region.

    ```yaml 
    - name: Enable-AWS-Security-Hub
      description: "CloudFormation Template to Enable AWS Security Hub for the Organization"
      resource_file: templates/enable-securityhub.yaml
      parameter_file: parameters/enable-securityhub.json
      deploy_method: stack_set
      deployment_targets:
        accounts:
          - # Either the 12-digit Account ID or the Logical Name for the Control Tower Management Account
      regions:
        - # AWS Region that is configured as the Home Region within Control Tower
    ```