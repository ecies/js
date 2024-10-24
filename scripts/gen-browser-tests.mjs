import fs from "node:fs";
import path from "node:path";

const handleFile = (srcPath, dstPath, ...pipelines) => {
  let data = fs.readFileSync(srcPath, "utf8");
  for (const f of pipelines) {
    data = f(data);
  }
  const dstDir = path.dirname(dstPath);
  if (!fs.existsSync(dstDir)) {
    fs.mkdirSync(dstDir);
  }
  fs.writeFileSync(dstPath, data);
};

const polyfill = `import { Buffer } from "buffer";
globalThis.Buffer = Buffer;

`;

const pipelines = [
  (data) => polyfill + data,
  (data) => data.replaceAll("../../src", "eciesjs"),
];

handleFile(
  "./tests/crypt/random.test.ts",
  "./tests-browser/crypt/random.test.ts",
  ...pipelines
);
handleFile(
  "./tests/crypt/known.test.ts",
  "./tests-browser/crypt/known.test.ts",
  ...pipelines
);
