#!/usr/bin/env bash

token=${1}
user=ab77
repository=netflix-proxy

if [[ -z ${1} ]]; then
    printf "Usage: ${0} <travis-ci-token>\n" 
    exit
fi

body='{
"request": {
  "message": "Scheduled build test",
  "branch": "master"
}}'

curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Travis-API-Version: 3" \
  -H "Authorization: token ${token}" \
  -d "${body}" \
  https://api.travis-ci.org/repo/${user}%2F${repository}/requests
