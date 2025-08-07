import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";

export class OwnHomeDataMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        let ownedBrawlersCount = Object.keys(player.ownedBrawlers).length;
        let ownedPinsCount = player.ownedPins.length;
        let ownedThumbnailsCount = player.ownedThumbnails.length;
        let ownedSkins = [];

        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            for (const skin of brawler.skins) {
                ownedSkins.push(skin);
            }
        }

        stream.writeVint(Math.floor(Date.now() / 1000)); // current timestamp
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeVint(player.trophies);
        stream.writeVint(player.highestTrophies);
        stream.writeVint(player.highestTrophies);
        stream.writeVint(player.trophyRoadTier);
        stream.writeVint(player.xp);
        stream.writeDataReference(28, player.thumbnail);
        stream.writeDataReference(43, player.namecolor);

        stream.writeVint(0);
        stream.writeVint(0); // selected skins
        stream.writeVint(0); // Randomizer selected skins
        stream.writeVint(0); // Current random skin
        stream.writeVint(600); // length of owned skins

        for (let i = 0; i < 600; i++) {
            stream.writeDataReference(29, i);
        }

        stream.writeVint(0); // unlocked skin purchase option
        stream.writeVint(0); // new item state
        stream.writeVint(0);
        stream.writeVint(player.highestTrophies);
        stream.writeVint(0);
        stream.writeVint(1);
        stream.writeBoolean(true);
        stream.writeVint(player.tokenDoublers);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeVint(999);
        stream.writeVint(999);
        stream.writeVint(5);
        stream.writeVint(999);
        stream.writeVint(999);
        stream.writeVint(999);
        stream.writeVint(999);
        stream.writeVint(999);

        stream.writeBoolean(false); // offer 1
        stream.writeBoolean(false); // offer 2
        stream.writeBoolean(true);  // token doubler enabled
        stream.writeVint(2);        // token double new tag state
        stream.writeVint(2);        // token double new tag state
        stream.writeVint(2);        // coin packs new tag state
        stream.writeVint(0);        // change name cost
        stream.writeVint(0);        // timer for next name change

        stream.writeVint(0); // offer count
        stream.writeVint(player.tokens);
        stream.writeVint(-1);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeVint(player.selectedBrawlers.length);
        for (const brawler of player.selectedBrawlers) {
            stream.writeDataReference(16, brawler);
        }

        stream.writeString(player.region);
        stream.writeString(player.supportedCreator);

        stream.writeVint(20);
        stream.writeLong(2, 1);  // Unknown
        stream.writeLong(3, 0);  // Tokens Gained
        stream.writeLong(4, 0);  // Trophies Gained
        stream.writeLong(6, 0);  // Demo Account
        stream.writeLong(7, 0);  // Invites Blocked
        stream.writeLong(8, 0);  // Star Points Gained
        stream.writeLong(9, 1);  // Show Star Points
        stream.writeLong(10, 0); // Power Play Trophies Gained
        stream.writeLong(12, 1); // Unknown
        stream.writeLong(14, 0); // Coins Gained
        stream.writeLong(15, 0); // AgeScreen | 3 = underage (disable soinstal media); | 1 = age popup
        stream.writeLong(16, 1);
        stream.writeLong(17, 0); // Team Chat Muted
        stream.writeLong(18, 0); // Esport Button
        stream.writeLong(19, 0); // Champion Ship Lives Buy Popup
        stream.writeLong(20, 0); // Gems Gained
        stream.writeLong(21, 0); // Looking For Team State
        stream.writeLong(22, 1);
        stream.writeLong(23, 0); // Club Trophies Gained
        stream.writeLong(24, 1); // Have already watched club league stupid animation

        stream.writeVint(0);

        // Brawlpass
        stream.writeVint(2);
        for (let i = 11; i < 13; i++) {
            stream.writeVint(i);
            stream.writeVint(34500);
            stream.writeBoolean(true);
            stream.writeVint(0);

            stream.writeByte(2);
            stream.writeInt(4294967292);
            stream.writeInt(4294967295);
            stream.writeInt(511);
            stream.writeInt(0);

            stream.writeByte(1);
            stream.writeInt(4294967292);
            stream.writeInt(4294967295);
            stream.writeInt(511);
            stream.writeInt(0);
        }

        stream.writeVint(0);
        stream.writeBoolean(true);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeBoolean(true);
        stream.writeVint(ownedPinsCount + ownedThumbnailsCount); // Vanity Count

        for (const pin of player.ownedPins) {
            stream.writeDataReference(52, pin);
            stream.writeVint(1);
            for (let i = 0; i < 1; i++) {
                stream.writeVint(1);
                stream.writeVint(1);
            }
        }

        for (const thumbnail of player.ownedThumbnails) {
            stream.writeDataReference(28, thumbnail);
            stream.writeVint(1);
            for (let i = 0; i < 1; i++) {
                stream.writeVint(1);
                stream.writeVint(1);
            }
        }

        stream.writeBoolean(false);
        stream.writeInt(0);
        stream.writeVint(0);
        stream.writeVint(25); // Count

        const vals = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 30, 31, 32];
        for (const value of vals) {
            stream.writeVint(value);
        }

        // Events
        stream.writeVint(3);
        let eventIndex = 1;
        const mapIDs = [5, 7, 24];
        for (const mapID of mapIDs) {
            stream.writeVint(-1);
            stream.writeVint(eventIndex);         // EventType
            stream.writeVint(0);                  // EventsBeginCountdown
            stream.writeVint(51208);              // Timer
            stream.writeVint(0);                  // tokens reward for new event
            stream.writeDataReference(15, mapID); // MapID
            stream.writeVint(-1);                 // GameModeVariation
            stream.writeVint(2);                  // State
            stream.writeString("");
            stream.writeVint(0);
            stream.writeVint(0);
            stream.writeVint(0);
            stream.writeVint(0); // Modifiers
            stream.writeVint(0);
            stream.writeVint(0);
            stream.writeBoolean(false); // Map Maker Map Structure Array
            stream.writeVint(0);
            stream.writeBoolean(false); // Power League Data Array
            stream.writeVint(0);
            stream.writeVint(0);
            stream.writeBoolean(false); // ChronosTextEntry
            stream.writeBoolean(false);
            stream.writeBoolean(false);
            stream.writeVint(-1);
            stream.writeBoolean(false);
            stream.writeBoolean(false);
            stream.writeVint(-1);
            eventIndex++;
        }

        stream.writeVint(0); // Coming Events

        const brawlerUpgradeCost = [20, 35, 75, 140, 290, 480, 800, 1250, 1875, 2800];
        const shopCoinsPrice = [20, 50, 140, 280];
        const shopCoinsAmount = [150, 400, 1200, 2600];

        stream.writeVint(brawlerUpgradeCost.length);
        for (const cost of brawlerUpgradeCost) {
            stream.writeVint(cost);
        }
        stream.writeVint(shopCoinsPrice.length);
        for (const price of shopCoinsPrice) {
            stream.writeVint(price);
        }
        stream.writeVint(shopCoinsAmount.length);
        for (const amount of shopCoinsAmount) {
            stream.writeVint(amount);
        }

        stream.writeBoolean(true); // Show Offers Packs
        stream.writeVint(0); // ReleaseEntry
        stream.writeVint(23); // IntValueEntry

        stream.writeLong(10008, 501);
        stream.writeLong(65, 2);
        stream.writeLong(1, 41000045); // ThemeID
        stream.writeLong(60, 36270);
        stream.writeLong(66, 1);
        stream.writeLong(61, 36270); // SupportDisabled State | if 36218 < state its true
        stream.writeLong(47, 41381);
        stream.writeLong(48, 41381);
        stream.writeLong(50, 0); // Coming up quests placeholder
        stream.writeLong(1100, 500);
        stream.writeLong(1101, 500);
        stream.writeLong(1003, 1);
        stream.writeLong(36, 0);
        stream.writeLong(14, 0); // Double Token Event
        stream.writeLong(31, 0); // Gold rush event
        stream.writeLong(79, 149999);
        stream.writeLong(80, 160000);
        stream.writeLong(28, 4);
        stream.writeLong(74, 1);
        stream.writeLong(78, 1);
        stream.writeLong(17, 4);
        stream.writeLong(10046, 1);
        stream.writeLong(87, 1);

        stream.writeVint(0); // Timed Int Value Entry
        stream.writeVint(0); // Custom Event
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeLong(player.id[1], player.id[0]);
        stream.writeVint(0);
        stream.writeVint(-1);
        stream.writeBoolean(false);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeBoolean(false);

        stream.writeVlong(player.id[0], player.id[1]);
        stream.writeVlong(0, 0);
        stream.writeVlong(0, 0);

        stream.writeString(player.name);
        stream.writeBoolean(true);
        stream.writeInt(0);
        stream.writeVint(16);

        stream.writeVint(3 + ownedBrawlersCount);

        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            stream.writeDataReference(23, brawler.cardID);
            stream.writeVint(-1);
            stream.writeVint(1);
        }

        stream.writeDataReference(5, 8);
        stream.writeVint(-1);
        stream.writeVint(player.coins);

        stream.writeDataReference(5, 10);
        stream.writeVint(-1);
        stream.writeVint(player.starpoints);

        stream.writeDataReference(5, 13);
        stream.writeVint(-1);
        stream.writeVint(0); // club coins

        stream.writeVint(ownedBrawlersCount);
        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            stream.writeDataReference(16, parseInt(brawlerKey));
            stream.writeVint(-1);
            stream.writeVint(brawler.trophies);
        }

        stream.writeVint(ownedBrawlersCount);
        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            stream.writeDataReference(16, parseInt(brawlerKey));
            stream.writeVint(-1);
            stream.writeVint(brawler.highestTrophies);
        }

        stream.writeVint(0);

        stream.writeVint(ownedBrawlersCount);
        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            stream.writeDataReference(16, parseInt(brawlerKey));
            stream.writeVint(-1);
            stream.writeVint(brawler.powerpoints);
        }

        stream.writeVint(ownedBrawlersCount);
        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            stream.writeDataReference(16, parseInt(brawlerKey));
            stream.writeVint(-1);
            stream.writeVint(brawler.powerlevel - 1);
        }

        stream.writeVint(0);

        stream.writeVint(ownedBrawlersCount);
        for (const brawlerKey in player.ownedBrawlers) {
            const brawler = player.ownedBrawlers[brawlerKey];
            stream.writeDataReference(16, parseInt(brawlerKey));
            stream.writeVint(-1);
            stream.writeVint(brawler.state);
        }

        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeVint(player.gems);  // Diamonds
        stream.writeVint(player.gems);  // Free Diamonds
        stream.writeVint(player.level); // Player Level

        stream.writeVint(100);
        stream.writeVint(0); // CumulativePurchasedDiamonds or Avatar User Level Tier
        stream.writeVint(0); // Battle Count
        stream.writeVint(0); // WinCount
        stream.writeVint(0); // LoseCount
        stream.writeVint(0); // WinLooseStreak
        stream.writeVint(0); // NpcWinCount
        stream.writeVint(0); // NpcLoseCount
        stream.writeVint(2); // TutorialState | shouldGoToFirstTutorialBattle = State == 0
        stream.writeVint(5);
        stream.writeVint(0);
        stream.writeVint(0);

        return stream.payload;
    }
}