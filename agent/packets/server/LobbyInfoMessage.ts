import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { config } from "../../definitions.js";

export class LobbyInfoMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        stream.writeVint(1);
        let info = "<c5c9ce9>N<c5699e8>B<c5195e7>S<c4b92e7> <c458ee6>O<c408be5>f<c3a87e4>f<c3584e4>l<c418be5>i<c4e93e7>n<c5a9ae8>e<c67a2ea> <c73aaec>V<c80b1ed>2<c8cb9ef>.<c99c1f1>3</c>\nMade by Natesworks\ndsc.gg/natesworks\nnbs.brawlmods.com"
        stream.writeString(`${info}\n${config.lobbyinfo}\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n`)
        stream.writeVint(0);
        return stream.payload;
    }
}
