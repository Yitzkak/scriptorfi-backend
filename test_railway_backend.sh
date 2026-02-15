#!/bin/bash
# Scriptorfi Railway Backend Test Script

RAILWAY_URL="https://web-production-3dd5.up.railway.app"

# 1. Test root URL

echo "\n== Testing root URL =="
curl -i "$RAILWAY_URL/"

# 2. Test token endpoint (login)
# Replace with a real username and password
USERNAME="yourusername"
PASSWORD="yourpassword"
echo "\n== Testing /api/token/ (login) =="
LOGIN_RESPONSE=$(curl -s -X POST "$RAILWAY_URL/api/token/" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN_RESPONSE"
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"access":"[^"]*' | grep -o '[^\"]*$')

# 3. Test registration endpoint
# Change username/email/password for each run to avoid duplicate errors
NEWUSER="testuser$(date +%s)"
NEWEMAIL="test$RANDOM@example.com"
NEWPASS="TestPassword123"
echo "\n== Testing /api/users/register/ =="
curl -i -X POST "$RAILWAY_URL/api/users/register/" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$NEWUSER\",\"email\":\"$NEWEMAIL\",\"password\":\"$NEWPASS\"}"

# 4. Test protected endpoint if token was received
if [ -n "$ACCESS_TOKEN" ]; then
  echo "\n== Testing /api/files/ with token =="
  curl -i "$RAILWAY_URL/api/files/" -H "Authorization: Bearer $ACCESS_TOKEN"
else
  echo "\nNo access token received, skipping protected endpoint test."
fi

echo "\n== Done =="
