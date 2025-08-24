import { base, config } from "./definitions.js";
import { Offsets } from "./offsets.js";

export function applyPatches() {
    // cursed code; maybe i should've used js
    (Memory as any).writeUtf8String(base.add(Offsets.EditControlsBrawler), "Silencer\0");
    //(Memory as any).writeUtf8String(base.add(Offsets.EditControlsMap), "Tutorial\0"); crashes
    (Memory as any).writeUtf8String(base.add(Offsets.GameBrawlStars), "127.0.0.1\0"); // NOT TO REDIRECT SERVER ITS TO FIX EXIT BUTTON AND LOBBYINFO NOT SHOWING
    (Memory as any).writeU8(base.add(Offsets.ArtTest), Number(config.artTest));
}