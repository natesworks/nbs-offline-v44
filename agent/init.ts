import { config, player } from "./definitions.js";
import { addDebugFile } from "./debugmenu.js";
import { installHooks } from "./mainHooks.js";
import { applyPatches } from "./patches.js";

player.applyConfig(config);
installHooks();
applyPatches();
//addDebugFile();