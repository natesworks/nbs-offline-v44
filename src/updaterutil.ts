import { debugMenuOpened, toggleDebugMenu } from "./debugmenu.js";
import { updaterConfig, updaterConfigPath, textFieldSetText, stableTextField, betaTextField, devTextField, showFloaterTextAtDefaultPos, guiGetInstance, reloadGameInternal, base, libPath } from "./definitions.js";
import { openFile, readFile, writeFile } from "./fs.js";
import { Logger } from "./logger.js";
import { closeFn, connectWithTimeout, httpBody, readAll, sendFn } from "./net.js";
import { Offsets } from "./offsets.js";
import { UpdaterConfig } from "./updaterconfig.js";
import { createStringObject, utf8ToBytes } from "./util";

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

export function unload() {
    if (debugMenuOpened)
        toggleDebugMenu();
    Interceptor.detachAll();
    Interceptor.revert(base.add(Offsets.MessagingSend));
    Interceptor.revert(base.add(Offsets.LogicCharacterServerTickAI));
    Interceptor.revert(base.add(Offsets.ApplicationOpenURL));
}

export function getUpdaterScript() {
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
    return readFile(fd);
}

export function update() {
    Script.evaluate("updater", getUpdaterScript());
}

export function switchBranch(branch: string) {
    Logger.debug("Switching branch to", branch);
    if (updaterConfig == null) return;
    updaterConfig.branch = branch;
    writeUpdaterConfig(updaterConfig);
    unload();
    reloadGameInternal(base.add(Offsets.GameMainInstance));
    update();
}

export function getBranches(): Map<string, string> | undefined {
    if (updaterConfig == null) return;
    const fd = connectWithTimeout(updaterConfig.ip, updaterConfig.port, 2000);
    if (fd < 0) {
        console.log('Failed to connect to server');
        return;
    }
    const reqStr = `GET /nbsoffline/script/${updaterConfig.version}/branches.json HTTP/1.1\r\nHost: ${updaterConfig.host}\r\nConnection: close\r\n\r\n`;
    Logger.debug("Getting branches from endpoint", `/nbsoffline/script/${updaterConfig.version}/branches.json`)
    const bytes = utf8ToBytes(reqStr);
    sendFn(fd, bytes.ptr, bytes.len, 0);
    const data = readAll(fd, 8000);
    closeFn(fd);
    if (data.length > 0) {
        const body = httpBody(data);
        //Logger.debug("Body:", body);
        if (body.length > 0) {
            try {
                const json = JSON.parse(body) as Record<string, string>;
                const map = new Map<string, string>();
                for (const key in json) {
                    map.set(key, json[key]);
                }
                return map;
            } catch {
                console.log('Failed to parse JSON');
                return;
            }
        }
    }
    console.log('Failed to connect to server');
}