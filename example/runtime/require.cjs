const { ECIES_CONFIG, utils: _utils } = require("eciesjs");
const config = require("eciesjs/config");
const consts = require("eciesjs/consts");
const utils = require("eciesjs/utils");

console.log("ECIES_CONFIG:", ECIES_CONFIG);
console.log("config:", config);
console.log("consts:", consts);
console.log("utils:", utils);
console.log("index utils:", _utils);
