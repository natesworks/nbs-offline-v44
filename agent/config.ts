import { open } from "fs";
import { Brawler } from "./brawler.js";
import { close, configPath, defaultConfigPath, libPath } from "./definitions.js";
import { Logger } from "./logger.js";
import { getLibraryDir, openFile, readFile, writeFile } from "./util.js";
import { config } from "process";

export class Config {
    static major = 44;
    static build = 226;
    static minor = 1;
    coins = 0;
    gems = 0;
    starpoints = 0;
    experienceLevel = 0;
    experience = 0;
    namecolor = 0;
    thumbnail = 0;
    trophyRoadTier = 0;
    tokens = 0;
    tokenDoublers = 0;
    trioWins = 0;
    soloWins = 0;
    duoWins = 0;
    challengeWins = 0;
    selectedBrawlers = [0, 1, 2];
    enableShop = false;
    enableBrawlPass = false;
    lobbyinfo = "";
    enableClubs = false;
    brawlPassPremium = true;
    ownedBrawlers: Record<number, Brawler> = [];
    disableBots = false;
    logToFile = false;
    infiniteAmmo = false;
    infiniteSuper = false;
    china = false;
}

export function tryLoadDefaultConfig() {
    let configFd = openFile(configPath);
    if (configFd >= 0) {
        close(configFd);
        return; // configuration file already exists
    }
    const defaultConfigFd = openFile(defaultConfigPath);
    if (defaultConfigFd < 0) {
        Logger.error("Failed to open default configuration file at", defaultConfigPath);
        throw new Error("Failed to open default configuration file");
    }
    configFd = openFile(configPath, true);
    const original = readFile(defaultConfigFd);
    const parsed = JSON.parse(original);
    const nbsSection = parsed.nbs;
    const jsonStr = JSON.stringify(nbsSection, null, 2);
    writeFile(configFd, jsonStr);
    close(defaultConfigFd);
    close(configFd);
}

export function readConfig() {
    const fd = openFile(configPath, true);
    if (fd < 0) {
        Logger.error("Failed to open configuration file at", configPath);
        throw Error("Failed to open configuration file");
    }
    const data = readFile(fd);
    const json = JSON.parse(data);

    const config = new Config();

    config.coins = json.coins;
    config.gems = json.gems;
    config.starpoints = json.starpoints;
    config.experienceLevel = json.level;
    config.experience = json.experience;
    config.namecolor = json.namecolor;
    config.thumbnail = json.thumbnail;
    config.trophyRoadTier = json["trophyRoadTier"];
    config.selectedBrawlers = json.selectedBrawlers;
    config.tokens = json.tokens;
    config.tokenDoublers = json.tokenDoublers;
    config.trioWins = json["3v3Victories"]; // cant use . cuz names with numbers are invalid thats also why i named it trio victories
    config.soloWins = json.soloVictories;
    config.duoWins = json.duoVictories;
    config.challengeWins = json.mostChallengeWins;
    config.lobbyinfo = json.lobbyinfo;
    config.enableBrawlPass = json.enableBrawlPass == null ? false : json.enableBrawlPass;
    config.enableShop = json.enableShop == null ? false : json.enableShop;
    config.enableClubs = json.enableClubs == null ? false : json.enableClubs;
    config.brawlPassPremium = json.brawlPassPremium == null ? true : json.brawlPassPremium;
    config.disableBots = json.disableBots == null ? false : json.disableBots;
    config.logToFile = json.logToFile == null ? false : json.logToFile;
    config.infiniteAmmo = json.infiniteAmmo == null ? false : json.infiniteAmmo;
    config.infiniteSuper = json.infiniteSuper == null ? false : json.infiniteSuper;
    config.china = json.china == null ? false : json.china;
    for (const [id, brawler] of Object.entries(json.unlockedBrawlers as Record<string, any>)) { // why does it have to be string sob
        config.ownedBrawlers[Number(id)] = new Brawler(
            brawler.cardID,
            brawler.skins,
            brawler.trophies,
            brawler.highestTrophies,
            brawler.powerlevel,
            brawler.powerpoints,
            brawler.state
        );
    }

    return config;
}