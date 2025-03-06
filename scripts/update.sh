#!/bin/sh
pnpm update --no-save
cd tests-browser && pnpm update && cd ..
cd example/browser && pnpm update && cd ..
