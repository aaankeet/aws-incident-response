# Dynamodb to store and record security incidents
resource "aws_dynamodb_table" "security_incidents" {
  name = "aws-security-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }
  tags = {
    Name = "AWS Security Incident Records"
  }
}
