#!/usr/bin/env bash

BRANCH=master

printf "build_branch=${TRAVIS_REPO_SLUG}:${TRAVIS_BRANCH}\n"
printf "pull_request=${TRAVIS_PULL_REQUEST}\n"
printf "target_branch=${GH_REPO}:${BRANCH}\n"

if [ "${TRAVIS_REPO_SLUG}" == "${GH_REPO}" ] && [ "${TRAVIS_PULL_REQUEST}" == "false" ] && [ "${TRAVIS_BRANCH}" == "${BRANCH}" ]; then
    exit 0
else
    exit 1
fi

