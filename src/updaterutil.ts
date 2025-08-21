import { libPath, updaterConfig, updaterConfigPath, close, logFile } from "./definitions";
import { openFile, readFile, writeFile } from "./fs.js";
import { Logger } from "./logger.js";
import { UpdaterConfig } from "./updaterconfig.js";

export function readUpdaterConfig(updaterConfigFile: number) {
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

export function writeUpdaterConfig(config: UpdaterConfig) {
    let str = JSON.stringify(config, null, 2);
    let updaterConfigFile = openFile(updaterConfigPath, true, true);
    writeFile(updaterConfigFile, str);
}

export function switchBranch(branch: string) {
    Logger.debug("Switching branch to", branch);
    updaterConfig.branch = branch;
    writeUpdaterConfig(updaterConfig);
}

export function update() {
    const primary = libPath + "/libNBS.l.so";
    const fallback = libPath + "/libloader.so";
    let fd = openFile(primary);
    if (fd < 0) {
        fd = openFile(fallback);
        if (fd < 0) {
            Logger.error("Failed to open:", primary, "or", fallback);
            throw new Error("Failed to open updater script");
        }
    }
    Interceptor.detachAll();
    close(logFile);
    const data = readFile(fd);
    Script.evaluate("updater", data);
    close(fd);
}