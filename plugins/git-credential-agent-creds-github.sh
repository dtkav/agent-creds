set -eu

operation=${1:-get}
case "$operation" in
    get)
        host=
        while IFS='=' read -r key value; do
            case "$key" in
                host) host=$value ;;
            esac
        done
        [ "$host" = github.com ] || exit 0
        token=${GIT_GITHUB_TOKEN:-}
        env_file=${AGENT_CREDS_ENV_FILE:-/run/adev-instance/sandbox.env}
        if [ -r "$env_file" ]; then
            while IFS= read -r line; do
                case "$line" in
                    GIT_GITHUB_TOKEN=*) token=${line#*=} ;;
                esac
            done < "$env_file"
        fi
        [ -n "$token" ] || exit 0
        printf 'username=x-access-token\npassword=%s\n' "$token"
        ;;
    store|erase)
        ;;
    *)
        exit 0
        ;;
esac
