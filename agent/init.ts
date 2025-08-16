import { open, read, write, pkg, config, player, load } from "./definitions.js";
import { addDebugFile } from "./debugmenu.js";
import { installHooks } from "./mainHooks.js";
import { applyPatches } from "./patches.js";
import { Logger } from "./logger.js";
import { readConfig } from "./config.js";

load();
player.applyConfig(config);
installHooks();
applyPatches();
//addDebugFile();