#!/bin/sh
pnpm update
cd tests-browser && pnpm update && cd ../example
cd browser && pnpm update && cd ..
cd runtime && pnpm update && cd ..
