#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

python threatlens/manage.py collectstatic --no-input
python threatlens/manage.py migrate
