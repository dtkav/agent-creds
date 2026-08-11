#!/bin/sh

vault_pid=""
ssh_pid=""

stop_children() {
    if [ -n "$vault_pid" ]; then
        kill "$vault_pid" 2>/dev/null || true
    fi
    if [ -n "$ssh_pid" ]; then
        kill "$ssh_pid" 2>/dev/null || true
    fi
    if [ -n "$vault_pid" ]; then
        wait "$vault_pid" 2>/dev/null || true
    fi
    if [ -n "$ssh_pid" ]; then
        wait "$ssh_pid" 2>/dev/null || true
    fi
}

shutdown() {
    trap - INT TERM
    stop_children
    exit 143
}

trap shutdown INT TERM

./vault &
vault_pid=$!
./vault-ssh &
ssh_pid=$!

wait "$vault_pid"
status=$?

trap - INT TERM
stop_children
exit "$status"
