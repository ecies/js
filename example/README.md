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

### Basic usage

Run `node main.js` or `bun run main.js` or `deno run --allow-read main.js`

### Check import

Run `node import.js` or `bun run import.js` or `deno run --allow-read import.js`
