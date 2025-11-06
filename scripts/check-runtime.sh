#!/bin/sh
bun run $1
deno run --conditions deno --allow-read $1
node $1
