#!/bin/sh
bun run $1
deno run --allow-read $1
node $1
