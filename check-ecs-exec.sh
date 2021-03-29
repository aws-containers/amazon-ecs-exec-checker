#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# shellcheck disable=SC2059

# Script Name: check-ecs-exec.sh
# Usage      : bash ./check-ecs-exec.sh <YOUR_ECS_CLUSTER_NAME> <YOUR_ECS_TASK_ID>

set -euo pipefail

## NOTE: Checks in this script are mainly based on:
##
##   "Using Amazon ECS Exec for debugging - Amazon Elastic Container Service"
##   https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
##
##   "NEW – Using Amazon ECS Exec to access your containers on AWS Fargate and Amazon EC2"
##   https://aws.amazon.com/blogs/containers/new-using-amazon-ecs-exec-access-your-containers-fargate-ec2/
##

## NOTE: This script needs the following permissions.
## {
##     "Version": "2012-10-17",
##     "Statement": [
##         {
##             "Effect": "Allow",
##             "Action": [
##                 "iam:GetInstanceProfile",
##                 "iam:SimulatePrincipalPolicy",
##                 "ec2:DescribeSubnets",
##                 "ec2:DescribeVpcEndpoints",
##                 "ecs:DescribeClusters",
##                 "ecs:DescribeContainerInstances",
##                 "ecs:DescribeTaskDefinition",
##                 "ecs:DescribeTasks"
##             ],
##             "Resource": "*"
##         }
##     ]
## }

# If you have multiple AWS CLI binaries, v1 and v2 for instance, you can choose which AWS CLI binary to use by setting the AWS_CLI_BIN env var.
# e.g. AWS_CLI_BIN=aws-v1 ./check-ecs-exec.sh YOUR_ECS_CLUSTER_NAME YOUR_ECS_TASK_ID
AWS_CLI_BIN=${AWS_CLI_BIN:-aws}

# Colors for output
COLOR_DEFAULT='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_GREEN='\033[0;32m'

# Validation for required parameters
CLUSTER_NAME=${1:-None} # A cluster name or a full ARN of the cluster
TASK_ID=${2:-None} # A task ID or a full ARN of the task
if [[ "x${CLUSTER_NAME}" = "xNone" || "x${TASK_ID}" = "xNone" ]]; then
  printf "${COLOR_RED}Usage:\n" >&2
  printf "  ./check-ecs-exec.sh YOUR_ECS_CLUSTER_NAME YOUR_ECS_TASK_ID\n" >&2
  exit 1
fi

#### Functions
printSectionHeaderLine() {
  printf "${COLOR_DEFAULT}-------------------------------------------------------------\n"
}
equalsOrGreaterVersion() {
  required=$1
  current=$2
  if [[ "$(printf '%s\n' "$required" "$current" | sort -V | head -n1)" = "$required" ]]; then
    return
  fi
  false
}
# For `iam simulate-principal-policy`
readEvalDecision() {
    evalResultsJson=$1
    actionName=$2
    echo "${evalResultsJson}" | jq -r --arg ACTION_NAME "$actionName" '.EvaluationResults[] | select(.EvalActionName==$ACTION_NAME) | .EvalDecision'
}
showEvalResult() {
    evalResult=$1
    actionName=$2
    printf "${COLOR_DEFAULT}     ${actionName}: "
    if [[ "x${evalResult}" = "xallowed" ]]; then
      printf "${COLOR_GREEN}${evalResult}\n"
    else
      printf "${COLOR_RED}${evalResult}\n"
    fi
}

## 1. CHECK PREREQUISITES FOR check-ecs-exec.sh ##########################################
printSectionHeaderLine
printf "${COLOR_DEFAULT}Prerequisites for check-ecs-exec.sh\n"
printSectionHeaderLine
##########################################################################################

# Check if jq command exists
command -v jq >/dev/null 2>&1 && status="$?" || status="$?"
if [[ ! "${status}" = 0 ]]; then
  printf "${COLOR_RED}Pre-flight check failed: \`jq\` command is missing\n" >&2
  exit 1
fi
printf "${COLOR_DEFAULT}  jq      | ${COLOR_GREEN}OK ${COLOR_DEFAULT}($(which jq))\n"

# Check if aws command exists
command -v "${AWS_CLI_BIN}" >/dev/null 2>&1 && status="$?" || status="$?"
if [[ ! "${status}" = 0 ]]; then
  printf "${COLOR_RED}Pre-flight check failed: \`${AWS_CLI_BIN}\` command is missing\n" >&2
  exit 1
fi
printf "${COLOR_DEFAULT}  AWS CLI | ${COLOR_GREEN}OK ${COLOR_DEFAULT}($(which "${AWS_CLI_BIN}"))\n"

## 2. CHECK PREREQUISITES FOR USING ECS EXEC FEATURE VIA AWS CLI #########################
printf "\n"
printSectionHeaderLine
printf "${COLOR_DEFAULT}Prerequisites for the AWS CLI to use ECS Exec\n"
printSectionHeaderLine
##########################################################################################

REGION=$(${AWS_CLI_BIN} configure get region)
AWS_REGION=${AWS_REGION:-$REGION}

callerIdentityJson=$(${AWS_CLI_BIN} sts get-caller-identity)
ACCOUNT_ID=$(echo "${callerIdentityJson}" | jq -r ".Account")
MY_IAM_ARN=$(echo "${callerIdentityJson}" | jq -r '.Arn |= sub("assumed-role"; "role") | .Arn')
MY_IAM_ARN="${MY_IAM_ARN%\/*}"

# Check task existence
describedTaskJson=$(${AWS_CLI_BIN} ecs describe-tasks \
  --cluster "${CLUSTER_NAME}" \
  --tasks "${TASK_ID}" \
  --output json)
existTask=$(echo "${describedTaskJson}" | jq -r ".tasks[0].taskDefinitionArn")
if [[ "x${existTask}" = "xnull" ]]; then
  printf "${COLOR_RED}Pre-flight check failed: The specified ECS task does not exist.\n\
Make sure the parameters you have specified for cluster \"${CLUSTER_NAME}\" and task \"${TASK_ID}\" are both valid.\n"
  exit 1
fi

# Check whether the AWS CLI v1.19.28/v2.1.30 or later exists
executeCommandEnabled=$(echo "${describedTaskJson}" | jq -r ".tasks[0].enableExecuteCommand")
if [[ "x${executeCommandEnabled}" = "xnull" ]]; then
  printf "${COLOR_RED}Pre-flight check failed: ECS Exec requires the AWS CLI v1.19.28/v2.1.30 or later.\n\
Please update the AWS CLI and try again?\n\
  For v2: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html\n\
  For v1: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv1.html\n"
  exit 1
fi
awsCliVersion=$(${AWS_CLI_BIN} --version 2>&1)
printf "${COLOR_DEFAULT}  AWS CLI Version        | ${COLOR_GREEN}OK ${COLOR_DEFAULT}(${awsCliVersion})\n"

# Check whether the Session Manager plugin exists
printf "${COLOR_DEFAULT}  Session Manager Plugin | "
command -v session-manager-plugin >/dev/null 2>&1 && status="$?" || status="$?"
if [[ "${status}" = 0 ]]; then
  smpVersion=$(session-manager-plugin --version)
  printf "${COLOR_GREEN}OK ${COLOR_DEFAULT}(${smpVersion})\n"
else
  # https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html
  printf "${COLOR_RED}Missing\n"
fi

## 3. CHECK CLUSTER AND TASK CONFIGURATIONS ##############################################
printf "\n"
printSectionHeaderLine
printf "${COLOR_DEFAULT}Configurations for ECS task and other resources\n"
printSectionHeaderLine
printf "${COLOR_DEFAULT}Cluster: ${CLUSTER_NAME}\n"
printf "${COLOR_DEFAULT}Task   : ${TASK_ID}\n"
printSectionHeaderLine
##########################################################################################

# 1. Checks on the cluster configurations
describedClusterJson=$(${AWS_CLI_BIN} ecs describe-clusters \
  --clusters "${CLUSTER_NAME}" \
  --include CONFIGURATIONS \
  --output json)
executeCommandConfigurationJson=$(echo "${describedClusterJson}" \
  | jq ".clusters[0].configuration.executeCommandConfiguration")

printf "${COLOR_DEFAULT}  Cluster Configuration  |"

kmsKeyId="null"
logging="null"
s3BucketName="null"
s3KeyPrefix="null"
s3Encryption="null"
cloudWatchLogGroupName="null"
cloudWatchLogEncryptionEnabled="null"
if [[ "x${executeCommandConfigurationJson}" = "xnull" ]]; then
  printf "${COLOR_YELLOW} Audit Logging Not Configured"
else
  printf "\n"

  kmsKeyId=$(echo "${executeCommandConfigurationJson}" | jq -r ".kmsKeyId")
  printf "${COLOR_DEFAULT}     KMS Key       : "
  if [[ "x${kmsKeyId}" = "xnull" ]]; then
    printf "${COLOR_YELLOW}Not Configured"
  else
    printf "${kmsKeyId}"
  fi
  printf "\n"

  logging=$(echo "${executeCommandConfigurationJson}" | jq -r ".logging")
  printf "${COLOR_DEFAULT}     Audit Logging : "
  if [[ "x${logging}" = "xnull" ]]; then
    printf "${COLOR_YELLOW}Not Configured"
  elif [[ "x${logging}" = "xNONE" ]]; then
    printf "${COLOR_YELLOW}Disabled"
  else
    printf "${logging}"
  fi
  printf "\n"

  s3BucketName=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.s3BucketName")
  s3KeyPrefix=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.s3KeyPrefix")
  s3Encryption=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.s3EncryptionEnabled")
  printf "${COLOR_DEFAULT}     S3 Bucket Name: "
  if [[ "x${s3BucketName}" = "xnull" ]]; then
    printf "Not Configured"
  else
    printf "${s3BucketName}"
    if [[ ! "x${s3KeyPrefix}" = "xnull" ]]; then
      printf ", Key Prefix: ${s3KeyPrefix}"
    fi
    printf ", Encryption Enabled: ${s3Encryption}"
  fi
  printf "\n"

  cloudWatchLogGroupName=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.cloudWatchLogGroupName")
  cloudWatchLogEncryptionEnabled=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.cloudWatchEncryptionEnabled")
  printf "${COLOR_DEFAULT}     CW Log Group  : "
  if [[ "x${cloudWatchLogGroupName}" = "xnull" ]]; then
    printf "Not Configured"
  else
    printf "${cloudWatchLogGroupName}"
    printf ", Encryption Enabled: ${cloudWatchLogEncryptionEnabled}"
  fi
fi
printf "\n"

# 2. Check whether "I" can call ecs:ExecuteCommand
printf "${COLOR_DEFAULT}  Can I ExecuteCommand?  | ${MY_IAM_ARN}\n"
ecsExecuteCommand="ecs:ExecuteCommand"
ecsExecEvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
    --policy-source-arn "${MY_IAM_ARN}" \
    --action-names "${ecsExecuteCommand}" \
    --resource-arns "arn:aws:ecs:${AWS_REGION}:${ACCOUNT_ID}:task/${CLUSTER_NAME}/${TASK_ID}" \
    --output json \
    | jq -r ".EvaluationResults[0].EvalDecision")
showEvalResult "${ecsExecEvalResult}" "${ecsExecuteCommand}"
if [[ ! "x${kmsKeyId}" = "xnull" ]]; then
  kmsGenerateDataKey="kms:GenerateDataKey"
  kmsGenerateDataKeyResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
    --policy-source-arn "${MY_IAM_ARN}" \
    --action-names "${kmsGenerateDataKey}" \
    --resource-arns "${kmsKeyId}" \
    --output json \
    | jq -r ".EvaluationResults[0].EvalDecision")
  showEvalResult "${kmsGenerateDataKeyResult}" "${kmsGenerateDataKey}"
fi
## Check for ensuring "I cannot" call ssm:StartSession 
### See the "Limiting access to the Start Session action" section at https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html#ecs-exec-limit-access-start-session
ssmStartSession="ssm:StartSession"
printf "${COLOR_DEFAULT}     ${ssmStartSession} denied?: "
ssmSessionEvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
    --policy-source-arn "${MY_IAM_ARN}" \
    --action-names "${ssmStartSession}" \
    --resource-arns "arn:aws:ecs:${AWS_REGION}:${ACCOUNT_ID}:task/${CLUSTER_NAME}/${TASK_ID}" \
    --output json \
    | jq -r ".EvaluationResults[0].EvalDecision")
if [[ "x${ssmSessionEvalResult}" = "xallowed" ]]; then
  printf "${COLOR_YELLOW}"
else
  printf "${COLOR_GREEN}"
fi
printf "${ssmSessionEvalResult}\n"

# 3. Check the launch type, platform version, ecs-agent version
launchType=$(echo "${describedTaskJson}" | jq -r ".tasks[0].launchType")
describedContainerInstanceJson=""
printf "${COLOR_DEFAULT}  Launch Type            | "
if [[ "x${launchType}" = "xFARGATE" ]]; then # For FARGATE Launch Type
  printf "${COLOR_GREEN}Fargate\n"
  # Check the PV
  printf "${COLOR_DEFAULT}  Platform Version       | "
  requiredPV="1.4.0"
  pv=$(echo "${describedTaskJson}" | jq -r ".tasks[0].platformVersion")
  if equalsOrGreaterVersion "${requiredPV}" "${pv}"; then
    printf "${COLOR_GREEN}${pv}"
  else
    printf "${COLOR_RED}${pv} (Required: >= ${requiredPV})"
  fi
  printf "\n"
elif [[ "x${launchType}" = "xEC2" ]]; then # For EC2 Launch Type
  printf "${COLOR_GREEN}EC2\n"
  # Check the ECS-Agent version
  containerInstanceArn=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containerInstanceArn")
  requiredAgentVersion="1.50.2"
  describedContainerInstanceJson=$(${AWS_CLI_BIN} ecs describe-container-instances \
    --cluster "${CLUSTER_NAME}" \
    --container-instance "${containerInstanceArn}" \
    --output json)
  agentVersion=$(echo "${describedContainerInstanceJson}" | jq -r ".containerInstances[0].versionInfo.agentVersion")
  printf "${COLOR_DEFAULT}  ECS Agent Version      | "
  if equalsOrGreaterVersion "${requiredAgentVersion}" "${agentVersion}"; then
    printf "${COLOR_GREEN}${agentVersion}"
  else
    printf "${COLOR_RED}${agentVersion} (Required: >= ${requiredAgentVersion})"
  fi
  printf "\n"
else
  printf "${COLOR_YELLOW}UNKNOWN\n"
fi

# 4. Check whether the `execute-command` option is enabled for the task
printf "${COLOR_DEFAULT}  Exec Enabled for Task  | "
if [[ "x${executeCommandEnabled}" = "xtrue" ]]; then
  printf "${COLOR_GREEN}OK"
else
  printf "${COLOR_RED}NO"
fi
printf "${COLOR_DEFAULT}\n"

# 5. Check the managed agents' status
printf "${COLOR_DEFAULT}  Managed Agent Status   | "
if [[ "x${executeCommandEnabled}" = "xfalse" ]]; then
  printf "${COLOR_DEFAULT}SKIPPED\n"
else
  printf "\n"
  agentsStatus=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[].managedAgents[].lastStatus")
  idx=0
  for _ in $agentsStatus; do
    containerName=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].name")
    status=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].managedAgents[0].lastStatus")
    reason=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].managedAgents[0].reason")
    printf "     $((idx+1)). "
    case "${status}" in
      *STOPPED* ) printf "${COLOR_RED}STOPPED (Reason: ${reason})";;
      *PENDING* ) printf "${COLOR_YELLOW}PENDING";;
      * ) printf "${COLOR_GREEN}RUNNING";;
    esac
    printf "${COLOR_DEFAULT} for \"${containerName}\" container\n"
    idx=$((idx+1))
  done
fi

# 6. Check the task role permissions
taskDefArn=$(echo "${describedTaskJson}" | jq -r ".tasks[0].taskDefinitionArn")
taskDefJson=$(${AWS_CLI_BIN} ecs describe-task-definition \
  --task-definition "${taskDefArn}" \
  --output json)
taskRoleArn=$(echo "${taskDefJson}" | jq -r ".taskDefinition.taskRoleArn")

hasRole=true
isEC2Role=false
if [[ "x${taskRoleArn}" = "xnull" ]]; then
  ## When the task runs on EC2 without a task role then we should check the instance profile
  if [[ "x${launchType}" = "xEC2" ]]; then
    ec2InstanceId=$(echo "${describedContainerInstanceJson}" | jq -r ".containerInstances[0].ec2InstanceId")
    instanceProfileArn=$(${AWS_CLI_BIN} ec2 describe-instances --instance-ids "${ec2InstanceId}" | jq -r ".Reservations[0].Instances[0].IamInstanceProfile.Arn")
    if [[ "x${instanceProfileArn}" = "xnull" ]]; then
      hasRole=false
    else
      instanceProfileName=$(echo "${instanceProfileArn}" | sed 's/arn:aws:iam::.*:instance-profile\///g')
      taskRoleArn=$(${AWS_CLI_BIN} iam get-instance-profile \
        --instance-profile-name "${instanceProfileName}" \
        | jq -r ".InstanceProfile.Roles[0].Arn")
      if [[ "x${taskRoleArn}" = "xnull" ]]; then
        hasRole=false
      else
        isEC2Role=true
      fi
    fi
  else
    ## Fargate launch type doesn't support to use EC2 instance roles
    hasRole=false
  fi
fi

if [[ ! "x${hasRole}" = "xtrue" ]]; then
  printf "${COLOR_DEFAULT}  EC2 or Task Role       | ${COLOR_RED}Not Configured"
else
  if [[ "x${isEC2Role}" = "xtrue" ]]; then
    printf "${COLOR_DEFAULT}  EC2 Role Permissions   | "
  else
    printf "${COLOR_DEFAULT}  Task Role Permissions  | "
  fi
  printf "${taskRoleArn}\n"
  ## Required Permissions
  ### SSM
  ssm="ssmmessages:"
  ssmCreateControlChannel="${ssm}CreateControlChannel"
  ssmCreateDataChannel="${ssm}CreateDataChannel"
  ssmOpenControlChannel="${ssm}OpenControlChannel"
  ssmOpenDataChannel="${ssm}OpenDataChannel"

  ssmEvalResultsJson=$(${AWS_CLI_BIN} iam simulate-principal-policy \
    --policy-source-arn "${taskRoleArn}" \
    --action-names "${ssmCreateControlChannel}" "${ssmCreateDataChannel}" "${ssmOpenControlChannel}" "${ssmOpenDataChannel}" \
    --output json)
  ssmCreateControlChannelResult=$(readEvalDecision "${ssmEvalResultsJson}" "${ssmCreateControlChannel}")
  showEvalResult "${ssmCreateControlChannelResult}" "${ssmCreateControlChannel}"
  ssmCreateDataChannelResult=$(readEvalDecision "${ssmEvalResultsJson}" "${ssmCreateDataChannel}")
  showEvalResult "${ssmCreateDataChannelResult}" "${ssmCreateDataChannel}"
  ssmOpenControlChannelResult=$(readEvalDecision "${ssmEvalResultsJson}" "${ssmOpenControlChannel}")
  showEvalResult "${ssmOpenControlChannelResult}" "${ssmOpenControlChannel}"
  ssmOpenDataChannelResult=$(readEvalDecision "${ssmEvalResultsJson}" "${ssmOpenDataChannel}")
  showEvalResult "${ssmOpenDataChannelResult}" "${ssmOpenDataChannel}"

  ## Optional Permissions (Might be required if audit-logging is enabled)
  ### KMS
  if [[ ! "x${kmsKeyId}" = "xnull" ]]; then
    printf "${COLOR_DEFAULT}     -----\n"
    kmsDecrypt="kms:Decrypt"
    kmsEvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
      --policy-source-arn "${taskRoleArn}" \
      --action-names "${kmsDecrypt}" \
      --output json \
      | jq -r ".EvaluationResults[0].EvalDecision")
    showEvalResult "${kmsEvalResult}" "${kmsDecrypt}"
  fi
  ### S3 Bucket
  if [[ ! "x${s3BucketName}" = "xnull" ]]; then
    printf "${COLOR_DEFAULT}     -----\n"
    s3PutObject="s3:PutObject"
    bucketArn="arn:aws:s3:::${s3BucketName}"
    resourceArn=""
    if [[ ! "x${s3KeyPrefix}" = "xnull" ]]; then
      resourceArn="${bucketArn}/${s3KeyPrefix}*"
    else
      resourceArn="${bucketArn}/*"
    fi
    s3EvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
      --policy-source-arn "${taskRoleArn}" \
      --action-names "${s3PutObject}" \
      --resource-arns "${resourceArn}" \
      --output json \
      | jq -r ".EvaluationResults[0].EvalDecision")
    showEvalResult "${s3EvalResult}" "${s3PutObject}"
    if [[ "x${s3Encryption}" = "xtrue" ]]; then
      s3GetEncryptionConfiguration="s3:GetEncryptionConfiguration"
      s3EvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
        --policy-source-arn "${taskRoleArn}" \
        --action-names "${s3GetEncryptionConfiguration}" \
        --resource-arns "${bucketArn}" \
        --output json \
        | jq -r ".EvaluationResults[0].EvalDecision")
      showEvalResult "${s3EvalResult}" "${s3GetEncryptionConfiguration}"
    fi
  fi
  ### CloudWatch Logs
  if [[ ! "x${cloudWatchLogGroupName}" = "xnull" ]]; then
    printf "${COLOR_DEFAULT}     -----\n"
    # For Resource "*"
    logsDescribeLogGroup="logs:DescribeLogGroups"
    logsDescribeLogGroupEvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
      --policy-source-arn "${taskRoleArn}" \
      --action-names "${logsDescribeLogGroup}" \
      --output json \
      | jq -r ".EvaluationResults[0].EvalDecision")
    showEvalResult "${logsDescribeLogGroupEvalResult}" "${logsDescribeLogGroup}"
    # For Resource "${cloudWatchLogGroupName}"
    cwlogGroupArn="arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${cloudWatchLogGroupName}:*"
    logsCreateLogStream="logs:CreateLogStream"
    logsDescribeLogStreams="logs:DescribeLogStreams"
    logsPutLogEvents="logs:PutLogEvents"
    logsEvalResultsJson=$(${AWS_CLI_BIN} iam simulate-principal-policy \
      --policy-source-arn "${taskRoleArn}" \
      --action-names "${logsCreateLogStream}" "${logsDescribeLogStreams}" "${logsPutLogEvents}" \
      --resource-arns "${cwlogGroupArn}" \
      --output json)
    logsCreateLogStreamResult=$(readEvalDecision "${logsEvalResultsJson}" "${logsCreateLogStream}")
    showEvalResult "${logsCreateLogStreamResult}" "${logsCreateLogStream}"
    logsDescribeLogStreamsResult=$(readEvalDecision "${logsEvalResultsJson}" "${logsDescribeLogStreams}")
    showEvalResult "${logsDescribeLogStreamsResult}" "${logsDescribeLogStreams}"
    logsPutLogEventsResult=$(readEvalDecision "${logsEvalResultsJson}" "${logsPutLogEvents}")
    showEvalResult "${logsPutLogEventsResult}" "${logsPutLogEvents}"
  fi
fi

# 7. Check existing VPC Endpoints (PrivateLinks) in the task VPC.
# If there is any VPC Endpoints configured for the task VPC, we assume you would need an additional SSM PrivateLink to be configured.
# TODO: In the ideal world, the script should simply check if the task can reach to the internet or not :)
taskNetworkingAttachment=$(echo "${describedTaskJson}" | jq -r ".tasks[0].attachments[0]")
taskVpcId=""
if [[ "x${taskNetworkingAttachment}" = "xnull" ]]; then
  ## bridge/host networking (only for EC2)
  taskVpcId=$(echo "${describedContainerInstanceJson}" | jq -r ".containerInstances[0].attributes[] | select(.name==\"ecs.vpc-id\") | .value")
else
  ## awsvpc networking (for both EC2 and Fargate)
  taskSubnetId=$(echo "${describedTaskJson}" | jq -r ".tasks[0].attachments[0].details[] | select(.name==\"subnetId\") | .value")
  taskVpcId=$(${AWS_CLI_BIN} ec2 describe-subnets --subnet-ids "${taskSubnetId}" | jq -r ".Subnets[0].VpcId")
fi
## List Vpc Endpoints
vpcEndpointsJson=$(${AWS_CLI_BIN} ec2 describe-vpc-endpoints \
  --filters Name=vpc-id,Values="${taskVpcId}")
vpcEndpoints=$(echo "${vpcEndpointsJson}" | tr -d '\n' | jq -r ".VpcEndpoints[]")
printf "${COLOR_DEFAULT}  VPC Endpoints          | "
if [[ "x${vpcEndpoints}" = "x" ]]; then
  printf "${COLOR_GREEN}SKIPPED ${COLOR_DEFAULT}(${taskVpcId} - No additional VPC endpoints required)\n"
else
  # Check whether an ssmmessages VPC endpoint exists
  vpcEndpoints=$(echo "${vpcEndpointsJson}" | tr -d '\n' | jq -r ".VpcEndpoints[].ServiceName")
  printf "\n"
  ssmsessionVpcEndpointExists=false
  requiredEndpoint="com.amazonaws.${AWS_REGION}.ssmmessages"
  for vpe in $vpcEndpoints; do
    if [[ "x${vpe}" = "x${requiredEndpoint}" ]]; then
      ssmsessionVpcEndpointExists=true
      break
    fi
  done

  printf "    Found existing endpoints for ${taskVpcId}:\n"  
  for vpe in $vpcEndpoints; do
    printf "      - ${COLOR_DEFAULT}${vpe}\n"
  done
  if [[ "x${ssmsessionVpcEndpointExists}" = "xfalse" ]]; then
    printf "    SSM PrivateLink \"${COLOR_YELLOW}${requiredEndpoint}${COLOR_DEFAULT}\" not found. You must ensure your task has proper outbound internet connectivity."
  fi
fi

printf "\n"
