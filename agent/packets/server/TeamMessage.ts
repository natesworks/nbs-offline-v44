import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { config } from "../../definitions.js";

export class TeamMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        return stream.payload;
    }
}