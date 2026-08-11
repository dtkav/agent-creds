set -eu

token=${GH_TOKEN:-}
env_file=${AGENT_CREDS_ENV_FILE:-/run/adev-instance/sandbox.env}
if [ -r "$env_file" ]; then
    while IFS= read -r line; do
        case "$line" in
            GH_TOKEN=*) token=${line#*=} ;;
        esac
    done < "$env_file"
fi
if [ -n "$token" ]; then
    export GH_TOKEN=$token
else
    unset GH_TOKEN
fi
exec @gh@ "$@"
