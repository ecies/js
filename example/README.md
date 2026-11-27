# example

Make sure `pnpm build` under the parent directory is run before.

## Browser example

Run `cd browser && pnpm install && pnpm dev`

> [!NOTE]
>
> You need to copy `.npmrc.windows` to `example/browser/.npmrc` on Windows before the command above

For production, run `pnpm build && pnpm preview`

## Runtime example (Node/Bun/Deno)

Run `cd runtime && pnpm install`

### Quick start

Run `node quick-start.js` or `bun run quick-start.js` or `deno run --conditions deno --allow-read quick-start.js`

### Basic usage

Run `node main.js` or `bun run main.js` or `deno run --conditions deno --allow-read main.js`

### Check import

Run `node import.js` or `bun run import.js` or `deno run --conditions deno --allow-read import.js`

### Check require

Run `node require.cjs` or `bun run require.cjs` or `deno run --conditions deno --allow-read require.cjs`

> [!NOTE]
>
> `--conditions deno` needs Deno 2.4.0 or later. See [Bun/Deno](../README.md#bundeno) for older versions.
