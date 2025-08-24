import { config, player, load } from "./definitions.js";
import { addDebugFile } from "./debugmenu.js";
import { installHooks } from "./mainHooks.js";
import { applyPatches } from "./patches.js";
import { Logger } from "./logger.js";

load();
Logger.info("Configuration loaded");
installHooks();
Logger.info("Hooks installed");
applyPatches();
Logger.info("Patches applied");
player.applyConfig(config);
addDebugFile();
Logger.info("NBS Offline loaded");