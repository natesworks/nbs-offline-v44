import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { config } from "../../definitions.js";

export class LobbyInfoMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        stream.writeVint(1);
        let info = "<c99c1f1>N<c99c1f1>B<c99c1f1>S<c99c1f1> <c99c1f1>O<c99c1f1>f<c99c1f1>f<c99c1f1>l<c99c1f1>i<c99c1f1>n<c99c1f1>e<c99c1f1> <c99c1f1>V<c99c1f1>4<c99c1f1>4</c>\nMade by Natesworks\ndsc.gg/natesworks\nnbs.brawlmods.com"
        stream.writeString(`${info}\n${config.lobbyinfo}\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n`)
        stream.writeVint(0);
        return stream.payload;
    }
}
