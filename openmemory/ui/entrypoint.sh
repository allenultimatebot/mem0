#!/bin/sh
set -e

# Ensure the working directory is correct
cd /app



for key in NEXT_PUBLIC_API_URL NEXT_PUBLIC_USER_ID; do
  value=$(printenv "$key" || true)
  [ -n "$value" ] || continue
  find .next/ -type f -exec sed -i "s|$key|$value|g" {} \;
done
echo "Done replacing env variables NEXT_PUBLIC_ with real values"

unset NEXT_PUBLIC_OPENMEMORY_API_TOKEN


if [ -n "${OPENMEMORY_API_TOKEN_FILE:-}" ] && [ -f "$OPENMEMORY_API_TOKEN_FILE" ]; then
  token_file=/tmp/openmemory-api-token
  cp "$OPENMEMORY_API_TOKEN_FILE" "$token_file"
  chown nextjs:nodejs "$token_file"
  chmod 0400 "$token_file"
  export OPENMEMORY_API_TOKEN_FILE="$token_file"
fi

# Execute the container's main process (CMD in Dockerfile)
exec su-exec nextjs "$@"
