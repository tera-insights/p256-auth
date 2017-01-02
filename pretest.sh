#!/bin/bash -e

# Courtesy of Jess

# Install necessary commandline tools
hash karma-cli 2>/dev/null || npm install -g karma-cli
hash webpack 2>/dev/null || npm install -g webpack