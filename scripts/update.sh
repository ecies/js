#!/bin/sh
pnpm update -i
cd tests-browser && pnpm update && cd ..
cd example/browser && pnpm update && cd ..
