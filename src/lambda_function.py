#! /usr/bin/env python
import boto3
import os
import logging


# define a logger using logging library. If LOG_LEVEL is not set, default to INFO.
# otherwise use value of LOG_LEVEL
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO'))


# define a lambda_handler function that takes in an event and a context
def lambda_handler(event, context):
    logger.info("Hello from Lambda!")

    # create a new boto3 client for the service 'sts'
    sts = boto3.client('sts')

    # get the id of the AWS account we're running in
    account_id = sts.get_caller_identity()["Account"]
    logger.info(f"I'm running in account {account_id}")

    # Return API Gateway compatible response format
    import json
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "statusMessage": "All OK",
            "accountId": account_id
        })
    }
