#!/usr/bin/env bash

BRANCH=master

if [ "${TRAVIS_REPO_SLUG}" == "${GH_REPO}" ] && [ "${TRAVIS_PULL_REQUEST}" == "false" ] && [ "${TRAVIS_BRANCH}" == "${BRANCH}" ]; then

  printf "Publishing artifacts from Travis build ${TRAVIS_BUILD_NUMBER} to ${TRAVIS_REPO_SLUG}:${TRAVIS_BRANCH}...\n"

  printf "artifacts: $(ls tests/artifacts/*.png | tr "\n" "; ")\n" 
  mkdir -p ${HOME}/artifacts && cp -R tests/artifacts/*.png ${HOME}/artifacts/

  cd ${HOME}
  git config --global user.email "${GH_EMAIL}"
  git config --global user.name "${GH_NAME}"
  git clone --quiet --branch=gh-pages https://${GH_TOKEN}@github.com/${GH_REPO} gh-pages > /dev/null

  cd gh-pages
  rm -rf artifacts && mkdir -p artifacts
  cp -Rf ${HOME}/artifacts/*.png artifacts/
  git add -f --all .
  git commit -m "Auto-push from Travis build ${TRAVIS_BUILD_NUMBER}"
  git push -fq origin gh-pages > /dev/null

  printf "Published artifacts to gh-pages.\n"
fi
