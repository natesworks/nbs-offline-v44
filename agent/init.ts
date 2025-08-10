import { addDebugFile } from "./debugmenu.js";
import { installHooks } from "./mainHooks.js";
import { applyPatches } from "./patches.js";

installHooks();
applyPatches();
addDebugFile();