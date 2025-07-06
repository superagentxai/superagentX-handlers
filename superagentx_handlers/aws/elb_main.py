import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import os


def main():
    """
    List AWS ALBs, listeners for each ALB, and target groups associated with each listener.
    Returns a dictionary containing all the information.
    """
    try:
        region = os.getenv("AWS_REGION")
        aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        # Initialize ELBv2 client
        elbv2_client = boto3.client(
            'elbv2',
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

        # Dictionary to store all ALB information
        alb_info = {}

        # Get all Application Load Balancers
        print("Fetching Application Load Balancers...")
        response = elbv2_client.describe_load_balancers()

        # Filter for Application Load Balancers only
        albs = [lb for lb in response['LoadBalancers'] if lb['Type'] == 'application']

        if not albs:
            print("No Application Load Balancers found.")
            return {}

        print(f"Found {len(albs)} Application Load Balancer(s)")

        for alb in albs:
            alb_arn = alb['LoadBalancerArn']
            alb_name = alb['LoadBalancerName']

            print(f"\nProcessing ALB: {alb_name}")

            # Initialize ALB entry in dictionary
            alb_info[alb_name] = {
                'arn': alb_arn,
                'dns_name': alb['DNSName'],
                'state': alb['State']['Code'],
                'scheme': alb['Scheme'],
                'vpc_id': alb['VpcId'],
                'availability_zones': [az['ZoneName'] for az in alb['AvailabilityZones']],
                'security_groups': alb.get('SecurityGroups', []),
                'listeners': {}
            }

            try:
                # Get listeners for this ALB
                listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
                listeners = listeners_response['Listeners']

                print(f"  Found {len(listeners)} listener(s)")

                for listener in listeners:
                    listener_arn = listener['ListenerArn']
                    listener_port = listener['Port']
                    listener_protocol = listener['Protocol']
                    listener_key = f"{listener_protocol}:{listener_port}"

                    print(f"    Processing listener: {listener_key}")

                    # Initialize listener entry
                    alb_info[alb_name]['listeners'][listener_key] = {
                        'arn': listener_arn,
                        'port': listener_port,
                        'protocol': listener_protocol,
                        'ssl_policy': listener.get('SslPolicy'),
                        'certificates': listener.get('Certificates', []),
                        'default_actions': listener.get('DefaultActions', []),
                        'target_groups': []
                    }

                    # Extract target groups from listener actions
                    target_group_arns = set()

                    # Check default actions for target groups
                    for action in listener.get('DefaultActions', []):
                        if action['Type'] == 'forward':
                            if 'TargetGroupArn' in action:
                                target_group_arns.add(action['TargetGroupArn'])
                            elif 'ForwardConfig' in action:
                                for target_group in action['ForwardConfig'].get('TargetGroups', []):
                                    target_group_arns.add(target_group['TargetGroupArn'])

                    # Get listener rules to find additional target groups
                    try:
                        rules_response = elbv2_client.describe_rules(ListenerArn=listener_arn)
                        rules = rules_response['Rules']

                        for rule in rules:
                            for action in rule.get('Actions', []):
                                if action['Type'] == 'forward':
                                    if 'TargetGroupArn' in action:
                                        target_group_arns.add(action['TargetGroupArn'])
                                    elif 'ForwardConfig' in action:
                                        for target_group in action['ForwardConfig'].get('TargetGroups', []):
                                            target_group_arns.add(target_group['TargetGroupArn'])

                    except ClientError as e:
                        print(f"      Error getting rules for listener {listener_key}: {e}")

                    # Get target group details
                    if target_group_arns:
                        try:
                            tg_response = elbv2_client.describe_target_groups(
                                TargetGroupArns=list(target_group_arns)
                            )

                            for tg in tg_response['TargetGroups']:
                                tg_arn = tg['TargetGroupArn']
                                tg_name = tg['TargetGroupName']

                                print(f"      Found target group: {tg_name}")

                                # Get target health for this target group
                                targets_health = []
                                try:
                                    health_response = elbv2_client.describe_target_health(
                                        TargetGroupArn=tg_arn
                                    )
                                    targets_health = health_response['TargetHealthDescriptions']
                                except ClientError as e:
                                    print(f"        Error getting target health for {tg_name}: {e}")

                                target_group_info = {
                                    'arn': tg_arn,
                                    'name': tg_name,
                                    'protocol': tg['Protocol'],
                                    'port': tg['Port'],
                                    'vpc_id': tg['VpcId'],
                                    'health_check_protocol': tg['HealthCheckProtocol'],
                                    'health_check_port': tg['HealthCheckPort'],
                                    'health_check_path': tg.get('HealthCheckPath'),
                                    'health_check_interval': tg['HealthCheckIntervalSeconds'],
                                    'health_check_timeout': tg['HealthCheckTimeoutSeconds'],
                                    'healthy_threshold': tg['HealthyThresholdCount'],
                                    'unhealthy_threshold': tg['UnhealthyThresholdCount'],
                                    'target_type': tg['TargetType'],
                                    'matcher': tg.get('Matcher', {}),
                                    'targets': []
                                }

                                # Add target health information
                                for target_health in targets_health:
                                    target = target_health['Target']
                                    health_state = target_health['TargetHealth']['State']

                                    target_info = {
                                        'id': target['Id'],
                                        'port': target.get('Port'),
                                        'availability_zone': target.get('AvailabilityZone'),
                                        'health_state': health_state,
                                        'health_description': target_health['TargetHealth'].get('Description', '')
                                    }
                                    target_group_info['targets'].append(target_info)

                                alb_info[alb_name]['listeners'][listener_key]['target_groups'].append(target_group_info)

                        except ClientError as e:
                            print(f"      Error getting target group details: {e}")

                    else:
                        print(f"      No target groups found for listener {listener_key}")

            except ClientError as e:
                print(f"  Error getting listeners for ALB {alb_name}: {e}")

        # Print summary
        print(f"\n=== SUMMARY ===")
        print(f"Total ALBs processed: {len(alb_info)}")

        total_listeners = sum(len(alb['listeners']) for alb in alb_info.values())
        print(f"Total listeners: {total_listeners}")

        total_target_groups = sum(
            len(listener['target_groups'])
            for alb in alb_info.values()
            for listener in alb['listeners'].values()
        )
        print(f"Total target groups: {total_target_groups}")

        # Optionally print the full dictionary (commented out due to potential size)
        # print(f"\n=== FULL CONFIGURATION ===")
        # print(json.dumps(alb_info, indent=2, default=str))

        return alb_info

    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.")
        return {}

    except ClientError as e:
        print(f"Error: AWS API call failed: {e}")
        return {}

    except Exception as e:
        print(f"Unexpected error: {e}")
        return {}


if __name__ == "__main__":
    result = main()

    # Example of how to access the data
    if result:
        print(f"\n=== EXAMPLE DATA ACCESS ===")
        for alb_name, alb_data in result.items():
            print(f"ALB: {alb_name}")
            print(f"  DNS: {alb_data['dns_name']}")
            print(f"  State: {alb_data['state']}")

            for listener_key, listener_data in alb_data['listeners'].items():
                print(f"  Listener: {listener_key}")
                print(f"    Target Groups: {len(listener_data['target_groups'])}")

                for tg in listener_data['target_groups']:
                    print(f"      - {tg['name']} ({len(tg['targets'])} targets)")