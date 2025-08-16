import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { config } from "../../definitions.js";

export class LobbyInfoMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        stream.writeVint(1);
        let info = "<c62a0ea>N<c62a0ea>B<c62a0ea>S<c62a0ea> <c62a0ea>O<c62a0ea>f<c61a0ea>f<c62a0ea>l<c62a0ea>i<c62a0ea>n<c62a0ea>e<c62a0ea> <c62a0ea>V<c62a0ea>2<c62a0ea>.<c61a0ea>3<c62a0ea>.<c62a0ea>1</c>\nMade by Natesworks\ndsc.gg/natesworks\nnbs.brawlmods.com"
        stream.writeString(`${info}\n${config.lobbyinfo}\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n`)
        stream.writeVint(0);
        return stream.payload;
    }
}
