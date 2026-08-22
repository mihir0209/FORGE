#!/bin/sh
set -eu

psql --username "$POSTGRES_USER" --dbname postgres \
  --set=forge_password="$FORGE_DB_PASSWORD" <<'SQL'
SELECT 'CREATE DATABASE inngest'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'inngest')\gexec

SELECT format('CREATE ROLE forge LOGIN PASSWORD %L', :'forge_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'forge')\gexec

SELECT 'CREATE DATABASE forge OWNER forge'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'forge')\gexec
SQL
