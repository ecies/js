# example

Make sure `pnpm build` under the parent directory is run before.

## Browser example

Run `cd browser && pnpm install && pnpm dev`

For production, run `pnpm build && pnpm preview`

## Runtime example (Node/Bun/Deno)

Run `cd runtime && bun install`

### Basic usage

Run `node main.js` or `bun run main.js` or `deno run --allow-read main.js`

### Check import

Run `node import.js` or `bun run import.js` or `deno run --allow-read import.js`
