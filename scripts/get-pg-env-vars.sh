#!/bin/bash

# ==============================================================================
# CNPG PSQL Environment Script Generator
#
# Description:
#   This script fetches the superuser connection details from a CloudNativePG
#   (CNPG) Kubernetes secret and generates a bash script containing the
#   necessary environment variables (PGHOST, PGPORT, etc.) for `psql`.
#
# Arguments:
#   $1 - namespace: The Kubernetes namespace where the CNPG cluster is deployed.
#   $2 - cluster-name: The name of the CNPG cluster.
#
# Usage:
#   1. Save this script as `generate_cnpg_env.sh`.
#   2. Make it executable: `chmod +x generate_cnpg_env.sh`
#   3. Run it and source its output to set the variables in your current shell:
#      source <(./generate_cnpg_env.sh <namespace> <cluster-name>)
#
# Example:
#   source <(./generate_cnpg_env.sh default my-postgres-cluster)
#
#   After running, you can connect to the database simply by typing:
#   psql
#
# ==============================================================================

set -euo pipefail

# --- Argument Validation ---
if [ "$#" -ne 2 ]; then
    echo "Error: Invalid number of arguments."
    echo "Usage: $0 <namespace> <cluster-name>"
    exit 1
fi

NAMESPACE=$1
CLUSTER_NAME=$2
# CNPG convention for the superuser secret name
SECRET_NAME="${CLUSTER_NAME}-superuser"
# SECRET_NAME="${CLUSTER_NAME}-app"

# --- Prerequisite Check ---
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl command not found. Please ensure it is installed and in your PATH."
    exit 1
fi

# --- Check for Secret Existence ---
echo "INFO: Looking for secret '${SECRET_NAME}' in namespace '${NAMESPACE}'..."
if ! kubectl get secret "${SECRET_NAME}" -n "${NAMESPACE}" > /dev/null 2>&1; then
    echo "Error: Secret '${SECRET_NAME}' not found in namespace '${NAMESPACE}'."
    echo "Please verify that the namespace and cluster name are correct."
    exit 1
fi
echo "INFO: Secret found."

# --- Helper Function to Decode Secret Data ---
# This function retrieves a specific key from the secret data, which is
# base64 encoded, and decodes it.
get_secret_value() {
    local key=$1
    local value
    # The jsonpath expression extracts the base64 encoded value for the given key.
    # The output is then piped to base64 for decoding.
    value=$(kubectl get secret "${SECRET_NAME}" \
        -n "${NAMESPACE}" \
        -o jsonpath="{.data.${key}}" 2>/dev/null | base64 --decode)

    if [ -z "$value" ]; then
        echo "Error: Could not find or decode key '${key}' in secret '${SECRET_NAME}'." >&2
        exit 1
    fi
    echo "$value"
}

# --- Fetch and Decode Connection Details ---
echo "INFO: Fetching and decoding connection details..."
PGHOST=$(get_secret_value "host")
PGPORT=$(get_secret_value "port")
PGUSER=$(get_secret_value "username")
PGPASSWORD=$(get_secret_value "password")
PGDATABASE=$(get_secret_value "dbname")
echo "INFO: Details successfully retrieved."

# --- Generate the Environment Variable Script ---
# This `cat` command with a HERE document (<< EOF) prints a block of text
# to standard output. The variables inside are expanded with the values
# we just retrieved from the secret. This output is what you will 'source'.
cat << EOF
# --- PSQL Environment for CNPG Cluster: ${CLUSTER_NAME} ---
# Source this file to configure your shell for psql.
# Example: source /path/to/this/output

export PGHOST='${PGHOST}'
export PGPORT='${PGPORT}'
export PGUSER='${PGUSER}'
export PGPASSWORD='${PGPASSWORD}'
export PGDATABASE='${PGDATABASE}'

# Optional: Set a custom prompt for psql
# export PSQL_PROMPT1="[%n@%m:%>(%`psql -c 'select case when pg_is_in_recovery() then 1 else 0 end' |grep -q 1 && echo RO || echo RW`%)%/%R] # "

echo "✓ PSQL environment variables are set for cluster '${CLUSTER_NAME}'."
echo "  You can now connect using the 'psql' command."
EOF

