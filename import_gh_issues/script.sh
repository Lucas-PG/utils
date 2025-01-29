#!/bin/bash

SRC_REPO="Lucas-PG/notes"
DEST_REPO=("Lucas-PG/teste")

for i in "${DEST_REPO[@]}"; do
  gh label clone "$SRC_REPO" -R "$i" # clona labels não existentes

  gh issue list --state open --limit 500 --json number -R "$SRC_REPO" |
    jq -r '.[] | .number' |
    while read issue; do
      gh issue transfer "$issue" "$i" -R "$SRC_REPO"
      sleep 3
    done
done
