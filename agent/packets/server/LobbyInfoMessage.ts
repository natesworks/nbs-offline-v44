import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";

export class LobbyInfoMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        stream.writeVint(1);
        stream.writeString("NBS Offline v2.2 Dev\nMade by Natesworks\ndsc.gg/natesworks\nnbs.brawlmods.com\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
        stream.writeVint(0);
        return stream.payload;
    }
}