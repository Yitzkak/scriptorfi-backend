#!/bin/bash
# Script to run migrations on Railway
# Usage: railway run bash run_migrations.sh

python manage.py migrate --noinput


