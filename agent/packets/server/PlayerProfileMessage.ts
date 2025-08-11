import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";

export class PlayerProfileMessage
{
    static encode(player: Player): number[]
    {
        let stream = new ByteStream([]);

        /* ***************************************** */
        stream.writeVlong(player.id[0], player.id[1]);
        stream.writeDataReference(0, -1);

        const ownedBrawlersCount = Object.keys(player.ownedBrawlers).length; // weird way to do it ngl; ts is weird; https://stackoverflow.com/questions/60033542/typescript-record-item-count
        stream.writeVint(ownedBrawlersCount);

        for (const [_brawlerID, brawlerData] of Object.entries(player.ownedBrawlers))
        {
            const brawlerID = Number(_brawlerID); // for some fucking reason brawlerID is a string now???
            stream.writeDataReference(16, brawlerID);
            stream.writeDataReference(0, -1); // skin
            stream.writeVint(brawlerData.trophies);
            stream.writeVint(brawlerData.highestTrophies);
            stream.writeVint(brawlerData.powerlevel);
        }

        stream.writeVint(16);
        stream.writeVint(1);
        stream.writeVint(player.trioVictories);
        stream.writeVint(2);
        stream.writeVint(player.xp);
        stream.writeVint(3);
        stream.writeVint(player.trophies);
        stream.writeVint(4);
        stream.writeVint(player.highestTrophies);
        stream.writeVint(5);
        stream.writeVint(ownedBrawlersCount);
        stream.writeVint(8);
        stream.writeVint(player.soloVictories);
        stream.writeVint(11);
        stream.writeVint(player.duoVictories);
        stream.writeVint(9);
        stream.writeVint(0);
        stream.writeVint(12);
        stream.writeVint(0);
        stream.writeVint(13);
        stream.writeVint(100);
        stream.writeVint(14);
        stream.writeVint(0);
        stream.writeVint(15);
        stream.writeVint(player.challengeWins);
        stream.writeVint(16);
        stream.writeVint(0);
        stream.writeVint(18);
        stream.writeVint(0);
        stream.writeVint(17);
        stream.writeVint(0);
        stream.writeVint(19);
        stream.writeVint(0);

        /* ***************************************** */
        stream.writeString(player.name);
        stream.writeVint(100);
        stream.writeVint(28000000 + player.thumbnail);
        stream.writeVint(43000000 + player.namecolor);
        stream.writeVint(0);

        /* ***************************************** */
        stream.writeBoolean(false);
        stream.writeDataReference(0, -1);

        return stream.payload;
    }
}
