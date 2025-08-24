import { updaterConfig, updaterConfigPath, textFieldSetText, stableTextField, betaTextField, devTextField, showFloaterTextAtDefaultPos, guiGetInstance } from "./definitions.js";
import { openFile, readFile, writeFile } from "./fs.js";
import { Logger } from "./logger.js";
import { UpdaterConfig } from "./updaterconfig.js";
import { createStringObject } from "./util";

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
    let stableText = "Stable";
    let betaText = "Beta";
    let devText = "Development";
    if (updaterConfig.branch == "stable") {
        stableText = `<c00ff00>${stableText}</c>`;
    }
    else if (updaterConfig.branch == "beta") {
        betaText = `<c00ff00>${betaText}</c>`;
    }
    else if (updaterConfig.branch == "dev") {
        devText = `<c00ff00>${devText}</c>`;
    }
    textFieldSetText(stableTextField, createStringObject(stableText));
    textFieldSetText(betaTextField, createStringObject(betaText));
    textFieldSetText(devTextField, createStringObject(devText));
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject("Please reload game to apply changes"), 0.0, -1);
}