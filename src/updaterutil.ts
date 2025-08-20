import { updaterConfig, updaterConfigPath } from "./definitions";
import { openFile, readFile, writeFile } from "./fs.js";
import { Logger } from "./logger.js";
import { UpdaterConfig } from "./updaterconfig.js";

export function readUpdaterConfig(updaterConfigFile : number)
{
    let config = new UpdaterConfig();
    let raw = readFile(updaterConfigFile);
    let json = JSON.parse(raw);
    config.arch = json.arch;
    config.branch = json.branch;
    config.host = json.host;
    config.ip = json.ip;
    config.port = json.port;
    config.version = json.version;
    return config;
}

export function writeUpdaterConfig(config : UpdaterConfig)
{
    let str = JSON.stringify(config, null, 2);
    let updaterConfigFile = openFile(updaterConfigPath, true, true);
    writeFile(updaterConfigFile, str);
}

export function switchBranch(branch: string)
{
    Logger.debug("Switching branch to", branch);
    updaterConfig.branch = branch;
    writeUpdaterConfig(updaterConfig);
}