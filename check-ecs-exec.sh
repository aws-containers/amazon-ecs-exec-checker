#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# shellcheck disable=SC2059

CHECKER_VERSION=v0.7

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

## NOTE: This script at least needs the following permissions. 
##       1. If you use an IAM user with an assumed role to run the script,
##          then you need to allow the "iam:ListRoles" action in addition to the following.
##       2. If you configured your ECS cluster to use KMS key for ECS Exec,
##          then you need to allow the "kms:DescribeKey" action in addition to the following.
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

# Force AWS CLI output format to json to use jq to parse its output
export AWS_DEFAULT_OUTPUT=json

# Colors for output
COLOR_DEFAULT='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_GREEN='\033[0;32m'

# Validation for required parameters
CLUSTER_NAME=${1:-None} # A cluster name or a full ARN of the cluster
TASK_ID=${2:-None} # A task ID or a full ARN of the task
if [[ "${CLUSTER_NAME}" = "None" || "${TASK_ID}" = "None" ]]; then
  printf "${COLOR_RED}Usage:\n" >&2
  printf "  ./check-ecs-exec.sh YOUR_ECS_CLUSTER_NAME YOUR_ECS_TASK_ID${COLOR_DEFAULT}\n" >&2
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
getRoleArnForAssumedRole() {
  callerIdentityJson=$1
  ROLE_ID=$(echo "${callerIdentityJson}" | jq -r ".UserId" | cut -d: -f1)
  aws iam list-roles --query "Roles[?RoleId=='${ROLE_ID}'].Arn" --output text
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
    if [[ "${evalResult}" = "allowed" ]]; then
      printf "${COLOR_GREEN}${evalResult}\n"
    else
      printf "${COLOR_RED}${evalResult}\n"
    fi
}

## 1. CHECK PREREQUISITES FOR check-ecs-exec.sh ##########################################
printSectionHeaderLine
printf "${COLOR_DEFAULT}Prerequisites for check-ecs-exec.sh ${CHECKER_VERSION}\n"
printSectionHeaderLine
##########################################################################################

# Check if jq command exists
command -v jq >/dev/null 2>&1 && status="$?" || status="$?"
if [[ ! "${status}" = 0 ]]; then
  printf "${COLOR_RED}Pre-flight check failed: \`jq\` command is missing${COLOR_DEFAULT}\n" >&2
  exit 1
fi
printf "${COLOR_DEFAULT}  jq      | ${COLOR_GREEN}OK ${COLOR_DEFAULT}($(which jq))\n"

# Check if aws command exists
command -v "${AWS_CLI_BIN}" >/dev/null 2>&1 && status="$?" || status="$?"
if [[ ! "${status}" = 0 ]]; then
  printf "${COLOR_RED}Pre-flight check failed: \`${AWS_CLI_BIN}\` command is missing${COLOR_DEFAULT}\n" >&2
  exit 1
fi
printf "${COLOR_DEFAULT}  AWS CLI | ${COLOR_GREEN}OK ${COLOR_DEFAULT}($(which "${AWS_CLI_BIN}"))\n"

# Find AWS region
REGION=$(${AWS_CLI_BIN} configure get region | tr -d "\r" || echo "")
export AWS_REGION=${AWS_REGION:-$REGION}
# Check region configuration in "source_profile" if the user uses MFA configurations
source_profile=$(${AWS_CLI_BIN} configure get source_profile || echo "")
if [ "${AWS_REGION}" = "" ] && [ "${source_profile}" != "" ]; then
  region=$(${AWS_CLI_BIN} configure get region --profile "${source_profile}" || echo "")
  export AWS_REGION="${region}"
fi
if [[ "${AWS_REGION}" = "" ]]; then
  printf "${COLOR_RED}Pre-flight check failed: Missing AWS region. Use the \`aws configure set default.region\` command or set the \"AWS_REGION\" environment variable.${COLOR_DEFAULT}\n" >&2
  exit 1
fi

## 2. CHECK PREREQUISITES FOR USING ECS EXEC FEATURE VIA AWS CLI #########################
printf "\n"
printSectionHeaderLine
printf "${COLOR_DEFAULT}Prerequisites for the AWS CLI to use ECS Exec\n"
printSectionHeaderLine
##########################################################################################

# MFA
AWS_MFA_SERIAL=${AWS_MFA_SERIAL:-$(${AWS_CLI_BIN} configure get mfa_serial || echo "")}
ROLE_TO_BE_ASSUMED=$(${AWS_CLI_BIN} configure get role_arn || echo "")
SOURCE_PROFILE=$(${AWS_CLI_BIN} configure get source_profile || echo "")
# Normally we don't need to ask MFA code thanks to the AWS CLI
# but we do need to prompt explicitly if the "AWS_MFA_SERIAL" value only exists without "role_arn" and "source_profile"
if [ "${AWS_MFA_SERIAL}" != "" ] && [ "${ROLE_TO_BE_ASSUMED}" == "" ] && [ "${SOURCE_PROFILE}" == "" ]; then
  # Prpmpt users to enter MFA code to obtain temporary credentials
  mfa_code=""
  while true; do
    printf "\n"
    printf "Type MFA code for ${AWS_MFA_SERIAL}: "
    read -rs mfa_code
    if [ -z "${mfa_code}" ]; then
       printf "${COLOR_RED}MFA code cannot be empty${COLOR_DEFAULT}"
       continue
    fi
    break
  done

  tmpCreds=$(${AWS_CLI_BIN} sts get-session-token --serial-number "${AWS_MFA_SERIAL}" --token-code "${mfa_code}")
  accessKey=$( echo "${tmpCreds}" | jq -r .Credentials.AccessKeyId )
  secretKey=$( echo "${tmpCreds}" | jq -r .Credentials.SecretAccessKey )
  sessionToken=$( echo "${tmpCreds}" | jq -r .Credentials.SessionToken )
  export AWS_ACCESS_KEY_ID="${accessKey}"
  export AWS_SECRET_ACCESS_KEY="${secretKey}"
  export AWS_SESSION_TOKEN="${sessionToken}"
fi

# Find caller identity
callerIdentityJson=$(${AWS_CLI_BIN} sts get-caller-identity)
ACCOUNT_ID=$(echo "${callerIdentityJson}" | jq -r ".Account")
CALLER_IAM_ARN=$(echo "${callerIdentityJson}" | jq -r ".Arn")
case "${CALLER_IAM_ARN}" in
  *:user/*|*:role/*|*:group/* ) MY_IAM_ARN="${CALLER_IAM_ARN}";;
  *:assumed-role/*) MY_IAM_ARN=$(getRoleArnForAssumedRole "${callerIdentityJson}");;
  * ) printf "${COLOR_RED}Pre-flight check failed: The ARN \"${CALLER_IAM_ARN}\" associated with the caller(=you) is not supported. Try again either with one of an IAM user, an IAM role, or an assumed IAM role.${COLOR_DEFAULT}\n" >&2 && exit 1;;
esac
if [[ "${MY_IAM_ARN}" = "" ]]; then
  printf "${COLOR_RED}Unknown error: Failed to get the role ARN of the caller(=you).${COLOR_DEFAULT}\n" >&2
  exit 1
fi

# Check task existence
describedTaskJson=$(${AWS_CLI_BIN} ecs describe-tasks \
  --cluster "${CLUSTER_NAME}" \
  --tasks "${TASK_ID}" \
  --output json)
existTask=$(echo "${describedTaskJson}" | jq -r ".tasks[0].taskDefinitionArn")
if [[ "${existTask}" = "null" ]]; then
  printf "${COLOR_RED}Pre-flight check failed: The specified ECS task does not exist.\n\
Make sure the parameters you have specified for cluster \"${CLUSTER_NAME}\" and task \"${TASK_ID}\" are both valid.${COLOR_DEFAULT}\n"
  exit 1
fi

# Check whether the AWS CLI v1.19.28/v2.1.30 or later exists
executeCommandEnabled=$(echo "${describedTaskJson}" | jq -r ".tasks[0].enableExecuteCommand")
if [[ "${executeCommandEnabled}" = "null" ]]; then
  printf "${COLOR_RED}Pre-flight check failed: ECS Exec requires the AWS CLI v1.19.28/v2.1.30 or later.\n\
Please update the AWS CLI and try again?\n\
  For v2: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html\n\
  For v1: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv1.html${COLOR_DEFAULT}\n"
  exit 1
fi
awsCliVersion=$(${AWS_CLI_BIN} --version 2>&1 | tr -d "\r")
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
printf "${COLOR_DEFAULT}Checks on ECS task and other resources\n"
printSectionHeaderLine
printf "${COLOR_DEFAULT}Region : ${AWS_REGION}\n"
printf "${COLOR_DEFAULT}Cluster: ${CLUSTER_NAME}\n"
printf "${COLOR_DEFAULT}Task   : ${TASK_ID}\n"
printSectionHeaderLine
##########################################################################################

# 1. Checks on the cluster configurations (yellow)
describedClusterJson=$(${AWS_CLI_BIN} ecs describe-clusters \
  --clusters "${CLUSTER_NAME}" \
  --include CONFIGURATIONS \
  --output json)
executeCommandConfigurationJson=$(echo "${describedClusterJson}" \
  | jq ".clusters[0].configuration.executeCommandConfiguration")

printf "${COLOR_DEFAULT}  Cluster Configuration  |"

kmsKeyId="null"
kmsKeyArn="null"
logging="null"
s3BucketName="null"
s3KeyPrefix="null"
s3Encryption="null"
cloudWatchLogGroupName="null"
cloudWatchLogEncryptionEnabled="null"
if [[ "${executeCommandConfigurationJson}" = "null" ]]; then
  printf "${COLOR_YELLOW} Audit Logging Not Configured"
else
  printf "\n"

  kmsKeyId=$(echo "${executeCommandConfigurationJson}" | jq -r ".kmsKeyId")
  printf "${COLOR_DEFAULT}     KMS Key       : "
  if [[ "${kmsKeyId}" = "null" ]]; then
    printf "${COLOR_YELLOW}Not Configured"
  else
    printf "${kmsKeyId}"
    kmsKeyArn=$(${AWS_CLI_BIN} kms describe-key --key-id "${kmsKeyId}" --query 'KeyMetadata.Arn' --output text)
  fi
  printf "\n"

  logging=$(echo "${executeCommandConfigurationJson}" | jq -r ".logging")
  printf "${COLOR_DEFAULT}     Audit Logging : "
  if [[ "${logging}" = "null" ]]; then
    printf "${COLOR_YELLOW}Not Configured"
  elif [[ "${logging}" = "NONE" ]]; then
    printf "${COLOR_YELLOW}Disabled"
  else
    printf "${logging}"
  fi
  printf "\n"

  s3BucketName=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.s3BucketName")
  s3KeyPrefix=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.s3KeyPrefix")
  s3Encryption=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.s3EncryptionEnabled")
  printf "${COLOR_DEFAULT}     S3 Bucket Name: "
  if [[ "${s3BucketName}" = "null" ]]; then
    printf "Not Configured"
  else
    printf "${s3BucketName}"
    if [[ ! "${s3KeyPrefix}" = "null" ]]; then
      printf ", Key Prefix: ${s3KeyPrefix}"
    fi
    printf ", Encryption Enabled: ${s3Encryption}"
  fi
  printf "\n"

  cloudWatchLogGroupName=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.cloudWatchLogGroupName")
  cloudWatchLogEncryptionEnabled=$(echo "${executeCommandConfigurationJson}" | jq -r ".logConfiguration.cloudWatchEncryptionEnabled")
  printf "${COLOR_DEFAULT}     CW Log Group  : "
  if [[ "${cloudWatchLogGroupName}" = "null" ]]; then
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
if [[ ! "${kmsKeyId}" = "null" ]]; then
  kmsGenerateDataKey="kms:GenerateDataKey"
  kmsGenerateDataKeyResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
    --policy-source-arn "${MY_IAM_ARN}" \
    --action-names "${kmsGenerateDataKey}" \
    --resource-arns "${kmsKeyArn}" \
    --output json \
    | jq -r ".EvaluationResults[0].EvalDecision")
  showEvalResult "${kmsGenerateDataKeyResult}" "${kmsGenerateDataKey}"
fi
## Check for ensuring "I cannot" call ssm:StartSession (yellow)
### See the "Limiting access to the Start Session action" section at https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html#ecs-exec-limit-access-start-session
ssmStartSession="ssm:StartSession"
printf "${COLOR_DEFAULT}     ${ssmStartSession} denied?: "
ssmSessionEvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
    --policy-source-arn "${MY_IAM_ARN}" \
    --action-names "${ssmStartSession}" \
    --resource-arns "arn:aws:ecs:${AWS_REGION}:${ACCOUNT_ID}:task/${CLUSTER_NAME}/${TASK_ID}" \
    --output json \
    | jq -r ".EvaluationResults[0].EvalDecision")
if [[ "${ssmSessionEvalResult}" = "allowed" ]]; then
  printf "${COLOR_YELLOW}"
else
  printf "${COLOR_GREEN}"
fi
printf "${ssmSessionEvalResult}\n"

# 3. Check the task is in RUNNING state
printf "${COLOR_DEFAULT}  Task Status            | "
taskStatus=$(echo "${describedTaskJson}" | jq -r ".tasks[0].lastStatus")
stoppedReason=$(echo "${describedTaskJson}" | jq -r ".tasks[0].stoppedReason")
case "${taskStatus}" in
  RUNNING ) printf "${COLOR_GREEN}${taskStatus}";;
  PROVISIONING|ACTIVATING|PENDING ) printf "${COLOR_YELLOW}${taskStatus}";;
  DEACTIVATING|STOPPING|DEPROVISIONING ) printf "${COLOR_RED}${taskStatus}";;
  STOPPED ) printf "${COLOR_RED}${taskStatus} (${stoppedReason})";;
  * ) printf "${COLOR_RED}${taskStatus}";;
esac
printf "${COLOR_DEFAULT}\n"

# 4. Check the launch type, platform version, ecs-agent version
launchType=$(echo "${describedTaskJson}" | jq -r ".tasks[0].launchType")
describedContainerInstanceJson=""
printf "${COLOR_DEFAULT}  Launch Type            | "
if [[ "${launchType}" = "FARGATE" ]]; then # For FARGATE Launch Type
  printf "${COLOR_GREEN}Fargate\n"
  # Check the PV
  printf "${COLOR_DEFAULT}  Platform Version       | "
  
  # Detect platform family to use correct platform version required
  pf=$(echo "${describedTaskJson}" | jq -r ".tasks[0].platformFamily")
  if [[ ${pf} == *"Windows"* ]]; then
    requiredPV="1.0.0"  #1.0.0 minimum for windows
  else
    requiredPV="1.4.0"  #1.4.0 for others
  fi
  
  pv=$(echo "${describedTaskJson}" | jq -r ".tasks[0].platformVersion")
  if equalsOrGreaterVersion "${requiredPV}" "${pv}"; then
    printf "${COLOR_GREEN}${pv}"
  else
    printf "${COLOR_RED}${pv} (Required: >= ${requiredPV})"
  fi
  printf "\n"
elif [[ "${launchType}" = "EC2" ]]; then # For EC2 Launch Type
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

# 5. Check whether the `execute-command` option is enabled for the task
printf "${COLOR_DEFAULT}  Exec Enabled for Task  | "
if [[ "${executeCommandEnabled}" = "true" ]]; then
  printf "${COLOR_GREEN}OK"
else
  printf "${COLOR_RED}NO"
fi
printf "${COLOR_DEFAULT}\n"

# 6. Check the managed agents' status
printf "${COLOR_DEFAULT}  Container-Level Checks | \n"
printf "${COLOR_DEFAULT}    ----------\n"
printf "${COLOR_DEFAULT}      Managed Agent Status"
if [[ "${executeCommandEnabled}" = "false" ]]; then
  printf " - ${COLOR_YELLOW}SKIPPED\n"
  printf "${COLOR_DEFAULT}    ----------\n"
else
  printf "\n"
  printf "${COLOR_DEFAULT}    ----------\n"
  agentsStatus=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[].managedAgents[].lastStatus")
  idx=0
  for _ in $agentsStatus; do
    containerName=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].name")
    status=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].managedAgents[0].lastStatus")
    reason=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].managedAgents[0].reason")
    lastStartedAt=$(echo "${describedTaskJson}" | jq -r ".tasks[0].containers[${idx}].managedAgents[0].lastStartedAt")
    printf "         $((idx+1)). "
    case "${status}" in
      *STOPPED* ) printf "${COLOR_RED}STOPPED (Reason: ${reason})";;
      *PENDING* ) printf "${COLOR_YELLOW}PENDING";;
      * ) printf "${COLOR_GREEN}RUNNING";;
    esac
    printf "${COLOR_DEFAULT} for \"${containerName}\""
    if [[ "${status}" = "STOPPED" ]]; then
      printf " - LastStartedAt: ${lastStartedAt}"
    fi
    printf "\n"
    idx=$((idx+1))
  done
fi

# 7. Check the "initProcessEnabled" flag added in the task definition (yellow)
taskDefArn=$(echo "${describedTaskJson}" | jq -r ".tasks[0].taskDefinitionArn")
taskDefJson=$(${AWS_CLI_BIN} ecs describe-task-definition \
  --task-definition "${taskDefArn}" \
  --output json)
taskDefFamily=$(echo "${taskDefJson}" | jq -r ".taskDefinition.family")
taskDefRevision=$(echo "${taskDefJson}" | jq -r ".taskDefinition.revision")
initEnabledList=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[].linuxParameters.initProcessEnabled")
idx=0
printf "${COLOR_DEFAULT}    ----------\n"
printf "${COLOR_DEFAULT}      Init Process Enabled (${taskDefFamily}:${taskDefRevision})\n"
printf "${COLOR_DEFAULT}    ----------\n"
for enabled in $initEnabledList; do
  containerName=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[${idx}].name")
  printf "         $((idx+1)). "
  case "${enabled}" in
    *true* ) printf "${COLOR_GREEN}Enabled";;
    *false* ) printf "${COLOR_YELLOW}Disabled";;
    * ) printf "${COLOR_YELLOW}Disabled";;
  esac
  printf "${COLOR_DEFAULT} - \"${containerName}\"\n"
  idx=$((idx+1))
done

# 8. Check the "readonlyRootFilesystem" flag added in the task definition (red)
readonlyRootFsList=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[].readonlyRootFilesystem")
idx=0
printf "${COLOR_DEFAULT}    ----------\n"
printf "${COLOR_DEFAULT}      Read-Only Root Filesystem (${taskDefFamily}:${taskDefRevision})\n"
printf "${COLOR_DEFAULT}    ----------\n"
for enabled in $readonlyRootFsList; do
  containerName=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[${idx}].name")
  printf "         $((idx+1)). "
  case "${enabled}" in
    *false* ) printf "${COLOR_GREEN}Disabled";;
    *true* ) printf "${COLOR_RED}ReadOnly";;
    * ) printf "${COLOR_GREEN}Disabled";;
  esac
  printf "${COLOR_DEFAULT} - \"${containerName}\"\n"
  idx=$((idx+1))
done

# 9. Check the task role permissions
overriddenTaskRole=true
taskRoleArn=$(echo "${describedTaskJson}" | jq -r ".tasks[0].overrides.taskRoleArn")
if [[ "${taskRoleArn}" = "null" ]]; then
  overriddenTaskRole=false
  taskRoleArn=$(echo "${taskDefJson}" | jq -r ".taskDefinition.taskRoleArn")
fi

hasRole=true
isEC2Role=false
if [[ "${taskRoleArn}" = "null" ]]; then
  ## When the task runs on EC2 without a task role then we should check the instance profile
  if [[ "${launchType}" = "EC2" ]]; then
    ec2InstanceId=$(echo "${describedContainerInstanceJson}" | jq -r ".containerInstances[0].ec2InstanceId")
    instanceProfileArn=$(${AWS_CLI_BIN} ec2 describe-instances --instance-ids "${ec2InstanceId}" | jq -r ".Reservations[0].Instances[0].IamInstanceProfile.Arn")
    if [[ "${instanceProfileArn}" = "null" ]]; then
      hasRole=false
    else
      instanceProfileName=$(echo "${instanceProfileArn}" | sed 's/arn:aws:iam::.*:instance-profile\///g')
      taskRoleArn=$(${AWS_CLI_BIN} iam get-instance-profile \
        --instance-profile-name "${instanceProfileName}" \
        | jq -r ".InstanceProfile.Roles[0].Arn")
      if [[ "${taskRoleArn}" = "null" ]]; then
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

if [[ ! "${hasRole}" = "true" ]]; then
  printf "${COLOR_DEFAULT}  EC2 or Task Role       | ${COLOR_RED}Not Configured\n"
else
  if [[ "${isEC2Role}" = "true" ]]; then
    printf "${COLOR_DEFAULT}  EC2 Role Permissions   | "
  else
    printf "${COLOR_DEFAULT}  Task Role Permissions  | "
  fi
  printf "${taskRoleArn}"
  if [[ "${overriddenTaskRole}" = "true" ]]; then
    printf " (Overridden)"
  fi
  printf "\n"
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
  if [[ ! "${kmsKeyId}" = "null" ]]; then
    printf "${COLOR_DEFAULT}     -----\n"
    kmsDecrypt="kms:Decrypt"
    kmsEvalResult=$(${AWS_CLI_BIN} iam simulate-principal-policy \
      --policy-source-arn "${taskRoleArn}" \
      --action-names "${kmsDecrypt}" \
      --resource-arns "${kmsKeyArn}" \
      --output json \
      | jq -r ".EvaluationResults[0].EvalDecision")
    showEvalResult "${kmsEvalResult}" "${kmsDecrypt}"
  fi
  ### S3 Bucket
  if [[ ! "${s3BucketName}" = "null" ]]; then
    printf "${COLOR_DEFAULT}     -----\n"
    s3PutObject="s3:PutObject"
    bucketArn="arn:aws:s3:::${s3BucketName}"
    resourceArn=""
    if [[ ! "${s3KeyPrefix}" = "null" ]]; then
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
    if [[ "${s3Encryption}" = "true" ]]; then
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
  if [[ ! "${cloudWatchLogGroupName}" = "null" ]]; then
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

# 10. Check existing VPC Endpoints (PrivateLinks) in the task VPC.
# If there is any VPC Endpoints configured for the task VPC, we assume you would need an additional SSM PrivateLink to be configured. (yellow)
# TODO: In the ideal world, the script should simply check if the task can reach to the internet or not :)
requiredEndpoint="com.amazonaws.${AWS_REGION}.ssmmessages"
taskNetworkingAttachment=$(echo "${describedTaskJson}" | jq -r ".tasks[0].attachments[0]")
if [[ "${taskNetworkingAttachment}" = "null" ]]; then
  ## bridge/host networking (only for EC2)
  taskVpcId=$(echo "${describedContainerInstanceJson}" | jq -r ".containerInstances[0].attributes[] | select(.name==\"ecs.vpc-id\") | .value")
  taskSubnetId=$(echo "${describedContainerInstanceJson}" | jq -r ".containerInstances[0].attributes[] | select(.name==\"ecs.subnet-id\") | .value")
  subnetJson=$(${AWS_CLI_BIN} ec2 describe-subnets --subnet-ids "${taskSubnetId}")
else
  ## awsvpc networking (for both EC2 and Fargate)
  taskSubnetId=$(echo "${describedTaskJson}" | jq -r ".tasks[0].attachments[0].details[] | select(.name==\"subnetId\") | .value")
  subnetJson=$(${AWS_CLI_BIN} ec2 describe-subnets --subnet-ids "${taskSubnetId}")
  taskVpcId=$(echo "${subnetJson}" | jq -r ".Subnets[0].VpcId")
fi
## Obtain the ownerID of subnet's owner to check if the subnet is shared via AWS RAM (which check-ecs-exec.sh doesn't support today)
subnetOwnerId=$(echo "${subnetJson}" | jq -r ".Subnets[0].OwnerId")
printf "${COLOR_DEFAULT}  VPC Endpoints          | "
if [[ ! "${ACCOUNT_ID}" = "${subnetOwnerId}" ]]; then
  ## Shared Subnets (VPC) are not supported in Amazon ECS Exec Checker
  printf "${COLOR_RED}CHECK FAILED${COLOR_YELLOW}\n"
  printf "     Amazon ECS Exec Checker doesn't support VPC endpoint validation for AWS RAM shared VPC/subnets.\n"
  printf "     Check or contact your administrator to find if additional VPC endpoints are required by the following resources.\n"
  printf "     - Resources: ${taskVpcId} and ${taskSubnetId}\n"
  printf "     - VPC Endpoint: ${requiredEndpoint}${COLOR_DEFAULT}\n"
else
  ## List Vpc Endpoints
  vpcEndpointsJson=$(${AWS_CLI_BIN} ec2 describe-vpc-endpoints \
    --filters Name=vpc-id,Values="${taskVpcId}")
  vpcEndpoints=$(echo "${vpcEndpointsJson}" | tr -d '\n' | jq -r ".VpcEndpoints[]")
  if [[ "${vpcEndpoints}" = "" ]]; then
    printf "${COLOR_GREEN}SKIPPED ${COLOR_DEFAULT}(${taskVpcId} - No additional VPC endpoints required)\n"
  else
    # Check whether an ssmmessages VPC endpoint exists
    vpcEndpoints=$(echo "${vpcEndpointsJson}" | tr -d '\n' | jq -r ".VpcEndpoints[].ServiceName")
    printf "\n"
    ssmsessionVpcEndpointExists=false
    for vpe in $vpcEndpoints; do
      if [[ "${vpe}" = "${requiredEndpoint}" ]]; then
        ssmsessionVpcEndpointExists=true
        break
      fi
    done

    printf "    Found existing endpoints for ${taskVpcId}:\n"  
    for vpe in $vpcEndpoints; do
      if [[ "${vpe}" = "${requiredEndpoint}" ]]; then
        printf "      - ${COLOR_GREEN}${vpe}${COLOR_DEFAULT}\n"
      else
        printf "      - ${COLOR_DEFAULT}${vpe}\n"
      fi
    done
    if [[ "${ssmsessionVpcEndpointExists}" = "false" ]]; then
      printf "    SSM PrivateLink \"${COLOR_YELLOW}${requiredEndpoint}${COLOR_DEFAULT}\" not found. You must ensure your task has proper outbound internet connectivity."
    fi
  fi
fi

# 11. Check task definition containers for environment variables AWS_ACCESS_KEY, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY
# if AWS_ACCESS_KEY, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY are defined in a container, they will be used by the SSM service
# if the key defined does not have requirement permissions, the execute-command will not work.
containerNameList=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[].name")
idx=0
printf "${COLOR_DEFAULT}  Environment Variables  | (${taskDefFamily}:${taskDefRevision})\n"
for containerName in $containerNameList; do
  printf "       ${COLOR_DEFAULT}$((idx+1)). container \"${containerName}\"\n"
  # find AWS_ACCESS_KEY
  printf "       ${COLOR_DEFAULT}- AWS_ACCESS_KEY"
  AWS_ACCESS_KEY_FOUND=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[${idx}].environment[] | select(.name==\"AWS_ACCESS_KEY\") | .name")
  case "${AWS_ACCESS_KEY_FOUND}" in
    *AWS_ACCESS_KEY* ) printf ": ${COLOR_YELLOW}defined${COLOR_DEFAULT}\n";;
    * ) printf ": ${COLOR_GREEN}not defined${COLOR_DEFAULT}\n";;
  esac
  # find AWS_ACCESS_KEY_ID
  printf "       ${COLOR_DEFAULT}- AWS_ACCESS_KEY_ID"
  AWS_ACCESS_KEY_ID_FOUND=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[${idx}].environment[] | select(.name==\"AWS_ACCESS_KEY_ID\") | .name")
  case "${AWS_ACCESS_KEY_ID_FOUND}" in
    *AWS_ACCESS_KEY_ID* ) printf ": ${COLOR_YELLOW}defined${COLOR_DEFAULT}\n";;
    * ) printf ": ${COLOR_GREEN}not defined${COLOR_DEFAULT}\n";;
  esac  
  # find AWS_SECRET_ACCESS_KEY
  printf "       ${COLOR_DEFAULT}- AWS_SECRET_ACCESS_KEY"
  AWS_SECRET_ACCESS_KEY_FOUND=$(echo "${taskDefJson}" | jq -r ".taskDefinition.containerDefinitions[${idx}].environment[] | select(.name==\"AWS_SECRET_ACCESS_KEY\") | .name")
  case "${AWS_SECRET_ACCESS_KEY_FOUND}" in
    *AWS_SECRET_ACCESS_KEY* ) printf ": ${COLOR_YELLOW}defined${COLOR_DEFAULT}\n";;
    * ) printf ": ${COLOR_GREEN}not defined${COLOR_DEFAULT}\n";;
  esac
  idx=$((idx+1))
done

printf "\n"
