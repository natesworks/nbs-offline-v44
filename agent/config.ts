import { Brawler } from "./brawler.js";
import { configPath } from "./definitions.js";
import { Logger } from "./logger.js";
import { getLibraryDir, openFile, readFile } from "./util.js";

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
}

export function readConfig() {
    const fd = openFile(configPath, true);
    const data = readFile(fd);
    const json = JSON.parse(data);

    const config = new Config();
    const nbs = json.nbs;

    config.coins = nbs.coins;
    config.gems = nbs.gems;
    config.starpoints = nbs.starpoints;
    config.experienceLevel = nbs.level;
    config.experience = nbs.experience;
    config.namecolor = nbs.namecolor;
    config.thumbnail = nbs.thumbnail;
    config.trophyRoadTier = nbs["trophyRoadTier"];
    config.selectedBrawlers = nbs.selectedBrawlers;
    config.tokens = nbs.tokens;
    config.tokenDoublers = nbs.tokenDoublers;
    config.trioWins = nbs["3v3Victories"]; // cant use . cuz names with numbers are invalid thats also why i named it trio victories
    config.soloWins = nbs.soloVictories;
    config.duoWins = nbs.duoVictories;
    config.challengeWins = nbs.mostChallengeWins;
    config.lobbyinfo = nbs.lobbyinfo;
    config.enableBrawlPass = nbs.enableBrawlPass == null ? false : nbs.enableBrawlPass;
    config.enableShop = nbs.enableShop == null ? false : nbs.enableShop;
    config.enableClubs = nbs.enableClubs == null ? false : nbs.enableClubs;
    config.brawlPassPremium = nbs.brawlPassPremium == null ? true : nbs.brawlPassPremium;
    config.disableBots = nbs.disableBots == null ? false : nbs.disableBots;
    config.logToFile = nbs.logToFile == null ? false : nbs.logToFile;
    config.infiniteAmmo = nbs.infiniteAmmo == null ? false : nbs.infiniteAmmo;
    for (const [id, brawler] of Object.entries(nbs.unlockedBrawlers as Record<string, any>)) { // why does it have to be string sob
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