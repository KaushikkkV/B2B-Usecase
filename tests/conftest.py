import os

# Ensure boto3 has deterministic test credentials before importing app modules
os.environ["AWS_ACCESS_KEY_ID"] = "testing-access-key"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-secret-key"
os.environ["AWS_SECURITY_TOKEN"] = "testing-token"
os.environ["AWS_SESSION_TOKEN"] = "testing-session-token"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"