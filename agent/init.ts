import { setup } from "./debugmenu.js";
import { installHooks } from "./mainHooks.js";
import { applyPatches } from "./patches.js";

installHooks();
applyPatches();
setup();