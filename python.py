#!/usr/bin/env python3

import boto3
import requests
import yaml
import ipaddress
from github import Github, Auth
from github.GithubException import UnknownObjectException
YAML_FILE = "template.yml"
CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
PUBLIC_IP_URL = "https://api.ipify.org"
IMDS = "http://169.254.169.254/latest"
# GitHub config
GITHUB_TOKEN = "ghp_yourtokenhere"  # GitHub Personal Access Token 
REPO_NAME = "Blodlad/task"
COMMIT_MSG = "Update template.yml after SG sync"
BRANCH = "master"
HOME_IP = "82.215.88.29/32" # Your Ip Address 
# -------------------------
# IMDS helpers (IMDSv2)
# -------------------------

def imds_token():
    return requests.put(
        f"{IMDS}/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        timeout=2,
    ).text


def imds(path, token):
    return requests.get(
        f"{IMDS}/meta-data/{path}",
        headers={"X-aws-ec2-metadata-token": token},
        timeout=2,
    ).text


# -------------------------
# Runtime discovery
# -------------------------

def get_region():
    session = boto3.session.Session()
    if session.region_name:
        return session.region_name

    token = imds_token()
    return imds("placement/region", token)


def get_security_group_ids():
    """
    Get ALL security group IDs attached to this instance
    via network interfaces (no DescribeInstances)
    """
    token = imds_token()
    sg_ids = set()

    macs = imds("network/interfaces/macs/", token).splitlines()

    for mac in macs:
        mac = mac.rstrip("/")
        groups = imds(f"network/interfaces/macs/{mac}/security-group-ids", token)
        for sg in groups.splitlines():
            sg_ids.add(sg.strip())

    if not sg_ids:
        raise RuntimeError("No security groups found via IMDS")

    return list(sg_ids)


# -------------------------
# External data
# -------------------------



def get_cloudflare_ipv4_ranges():
    r = requests.get(CLOUDFLARE_IPV4_URL, timeout=10)
    r.raise_for_status()
    return sorted(set(r.text.splitlines()))


# -------------------------
# YAML helpers
# -------------------------

def load_yaml():
    with open(YAML_FILE) as f:
        return yaml.safe_load(f)


def save_yaml(data):
    with open(YAML_FILE, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)



# -------------------------
# Security Group logic
# -------------------------

def extract_http_cidrs(sg):
    cidrs = set()
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") == "tcp" and \
           perm.get("FromPort") == 80 and \
           perm.get("ToPort") == 80:
            for r in perm.get("IpRanges", []):
                cidrs.add(r["CidrIp"])
    return cidrs


def revoke_http(ec2, sg_id, cidrs):
    if cidrs:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": c} for c in cidrs]
            }]
        )


def authorize_http(ec2, sg_id, cidrs):
    if cidrs:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": c} for c in cidrs]
            }]
        )
def push_to_github():
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = g.get_repo(REPO_NAME)  # e.g., "username/repo"

    with open(YAML_FILE, "r") as f:
        content_str = f.read()

    try:
        file = repo.get_contents(YAML_FILE, ref=BRANCH)
        # File exists, update it
        repo.update_file(file.path, COMMIT_MSG, content_str, file.sha, branch=BRANCH)
        print(f"{YAML_FILE} updated successfully and pushed to repo!")
    except UnknownObjectException:
        # File does not exist (404), create it
        repo.create_file(YAML_FILE, COMMIT_MSG, content_str, branch=BRANCH)
        print(f"{YAML_FILE} created and pushed successfully!")
# -------------------------
# Main
# -------------------------

def main():
    region = get_region()
    ec2 = boto3.client("ec2", region_name=region)

    state = load_yaml()

    cloudflare_ips = get_cloudflare_ipv4_ranges()

    desired_http = set(cloudflare_ips)
    desired_http.add(HOME_IP)

    sg_ids = get_security_group_ids()

    for sg_id in sg_ids:
        sg = ec2.describe_security_groups(
            GroupIds=[sg_id]
        )["SecurityGroups"][0]

        existing_http = extract_http_cidrs(sg)

        to_remove = existing_http - desired_http
        to_add = desired_http - existing_http

        revoke_http(ec2, sg_id, existing_http - desired_http)
        authorize_http(ec2, sg_id, desired_http - existing_http)
        # Final rule counts
        sg_final = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        final_http = extract_http_cidrs(sg_final)

        # Count SSH rules (port 22)
        final_ssh = set()
       for perm in sg_final.get("IpPermissions", []):
            if perm.get("IpProtocol") == "tcp" and perm.get("FromPort") == 22 and perm.get("ToPort") == 22:
                for r in perm.get("IpRanges", []):
                    final_ssh.add(r["CidrIp"])

    # Update YAML template
    state.setdefault("rules", {})
    state["rules"]["ssh"] = ["0.0.0.0/0"]
    state["rules"]["http"] = sorted(desired_http)

    save_yaml(state)

    print("Security Group sync complete")
    print(f"\nSyncing SG: {sg_id}")
    print(f"Existing HTTP CIDRs ({len(existing_http)}): {sorted(existing_http)}")
    print(f"Planned adds ({len(to_add)}): {sorted(to_add)}")
    print(f"Planned removes ({len(to_remove)}): {sorted(to_remove)}")
    print(f"Detected home IP: {HOME_IP}")
    print(f"Final HTTP CIDRs ({len(final_http)}): {sorted(final_http)}")
    print(f"Final SSH CIDRs ({len(final_ssh)}): {sorted(final_ssh)}")
    print(f"Final SG rule count (HTTP + SSH): {len(final_http) + len(final_ssh)}")
    # Push updated YAML to GitHub
    push_to_github()

if __name__ == "__main__":
    main()    
