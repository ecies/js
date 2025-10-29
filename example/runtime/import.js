import { ECIES_CONFIG, utils as _utils } from "eciesjs";
import * as config from "eciesjs/config";
import * as consts from "eciesjs/consts";
import utils from "eciesjs/utils"; // Default import now supported
import * as utilsNamespace from "eciesjs/utils"; // Namespace import still works

console.log("ECIES_CONFIG:", ECIES_CONFIG);
console.log("config:", config);
console.log("consts:", consts);
console.log("utils (default import):", utils);
console.log("utils (namespace import):", utilsNamespace);
console.log("index utils:", _utils);
