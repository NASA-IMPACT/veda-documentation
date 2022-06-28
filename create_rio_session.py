import boto3
import os
import rasterio as rio
from rasterio.session import AWSSession

# Assume the AWS profile already has access to assume the role
sts_client = boto3.client("sts")

role_session_name = 'svi-access'

assumed_role_object = sts_client.assume_role(
    # Replace this with role you have been given to assume
    RoleArn=os.environ['AWS_ROLE'],
    RoleSessionName=role_session_name
)

# Use the credentials returned to upload to the staging bucket
credentials = assumed_role_object["Credentials"]
access_key_id = assumed_role_object["Credentials"]["AccessKeyId"]
secret_access_key = assumed_role_object["Credentials"]["SecretAccessKey"]
session_token = assumed_role_object["Credentials"]["SessionToken"]

session = boto3.Session(aws_access_key_id=access_key_id, 
                        aws_secret_access_key=secret_access_key,
                        aws_session_token=session_token)

if __name__ == "__main__":
    rio_env = rio.Env(AWSSession(session),
                      GDAL_DISABLE_READDIR_ON_OPEN='EMPTY_DIR',
                      GDAL_HTTP_COOKIEFILE=os.path.expanduser('~/cookies.txt'),
                      GDAL_HTTP_COOKIEJAR=os.path.expanduser('~/cookies.txt'))
    rio_env.__enter__()
