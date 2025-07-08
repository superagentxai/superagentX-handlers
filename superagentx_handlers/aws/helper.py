import boto3
import os


def generate_aws_sts_token(region_name: str,
                           aws_access_key_id: str,
                           aws_secret_access_key: str,
                           duration_seconds=3600):
    """
    Generate AWS STS temporary credentials.
    :param region_name: AWS Region Name
    :param aws_access_key_id: AWS Access Key
    :param aws_secret_access_key: AWS Secret Key
    :param duration_seconds: Duration in seconds for the session (900 to 129600)
    :return: Dictionary with AccessKeyId, SecretAccessKey, SessionToken, and Expiration
    """
    # Create a boto3 STS client (uses environment credentials or IAM role by default)
    region = region_name or os.getenv("AWS_REGION") or "us-east-1"
    aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

    sts_client = boto3.client('sts',
                              region_name=region,
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key
                              )

    # Get session token
    response = sts_client.get_session_token(DurationSeconds=duration_seconds)
    credentials = response['Credentials']

    # Return the credentials
    return {
        'region_name': region,
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'aws_session_token': credentials['SessionToken'],
    }


# Example usage
if __name__ == "__main__":
    creds = generate_aws_sts_token()
    print("Temporary credentials:")
    for key, value in creds.items():
        print(f"{key}: {value}")
