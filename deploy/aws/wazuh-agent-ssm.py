#!/usr/bin/env python3
"""Create or update the BlakSOC-WazuhAgent SSM document and the State Manager association that runs it on
every managed Linux instance (new ones as they register, all of them daily). Usage: wazuh-agent-ssm.py
The enrolment password is read from Secrets Manager and stored as the association's parameter, which AWS
administrators can read; it only allows agent enrolment. Never printed."""
import json, pathlib, re, subprocess

REGION = "ap-southeast-2"
DOC = "BlakSOC-WazuhAgent"
aws = ["aws", "--region", REGION]
here = pathlib.Path(__file__).resolve().parent
body = (here / "wazuh-agent.sh").read_text().split("\n", 1)[1]
pw = json.loads(subprocess.check_output(aws + ["secretsmanager", "get-secret-value", "--secret-id", "blaksoc-wazuh-credentials", "--query", "SecretString", "--output", "text"], text=True))["ENROLLMENT_PASSWORD"]
assert re.fullmatch(r"[A-Za-z0-9]+", pw)

content = {
    "schemaVersion": "2.2",
    "description": "Install and enrol the blakSOC Wazuh agent (deploy/aws/wazuh-agent.sh). Safe to re-run.",
    "parameters": {"EnrollmentPassword": {"type": "String", "description": "Wazuh enrolment password"}},
    "mainSteps": [{
        "action": "aws:runShellScript", "name": "wazuhAgent", "precondition": {"StringEquals": ["platformType", "Linux"]},
        "inputs": {"timeoutSeconds": "900", "runCommand": ["#!/usr/bin/env bash", "export WAZUH_REGISTRATION_PASSWORD='{{ EnrollmentPassword }}'", body]},
    }],
}
doc = json.dumps(content)
exists = subprocess.run(aws + ["ssm", "describe-document", "--name", DOC], capture_output=True).returncode == 0
if exists:
    v = subprocess.check_output(aws + ["ssm", "update-document", "--name", DOC, "--content", doc, "--document-version", "$LATEST", "--query", "DocumentDescription.DocumentVersion", "--output", "text"], text=True).strip()
    subprocess.run(aws + ["ssm", "update-document-default-version", "--name", DOC, "--document-version", v], check=True, stdout=subprocess.DEVNULL)
else:
    subprocess.run(aws + ["ssm", "create-document", "--name", DOC, "--document-type", "Command", "--content", doc, "--tags", "Key=Project,Value=yumait-eks", "Key=App,Value=blaksoc"], check=True, stdout=subprocess.DEVNULL)
print("document", "updated" if exists else "created")

assoc = json.loads(subprocess.check_output(aws + ["ssm", "list-associations", "--association-filter-list", f"key=Name,value={DOC}", "--query", "Associations[].AssociationId"], text=True))
params = json.dumps({"EnrollmentPassword": [pw]})
common = ["--parameters", params, "--schedule-expression", "rate(1 day)", "--targets", "Key=InstanceIds,Values=*", "--max-concurrency", "5", "--max-errors", "100%", "--association-name", "blaksoc-wazuh-agent"]
if assoc:
    subprocess.run(aws + ["ssm", "update-association", "--association-id", assoc[0], "--name", DOC, "--document-version", "$DEFAULT"] + common, check=True, stdout=subprocess.DEVNULL)
    print("association updated", assoc[0])
else:
    out = subprocess.check_output(aws + ["ssm", "create-association", "--name", DOC] + common + ["--query", "AssociationDescription.AssociationId", "--output", "text"], text=True).strip()
    print("association created", out)
