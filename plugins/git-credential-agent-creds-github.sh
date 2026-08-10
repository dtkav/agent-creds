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
        [ -n "${GIT_GITHUB_TOKEN:-}" ] || exit 0
        printf 'username=x-access-token\npassword=%s\n' "$GIT_GITHUB_TOKEN"
        ;;
    store|erase)
        ;;
    *)
        exit 0
        ;;
esac
