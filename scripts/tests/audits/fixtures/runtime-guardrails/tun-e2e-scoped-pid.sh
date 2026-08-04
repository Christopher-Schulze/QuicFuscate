#!/usr/bin/env bash

start_server() {
  SERVER_PID=$!
}

CLIENT_PID=$!

cleanup_on_exit() {
  stop_owned_process "$CLIENT_PID"
  stop_owned_process "$SERVER_PID"
}

trap cleanup_on_exit EXIT
