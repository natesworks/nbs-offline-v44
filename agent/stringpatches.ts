import { base } from "./definitions.js";
import { Offsets } from "./offsets.js";

export function patchStrings()
{
    (Memory as any).writeUtf8String(base.add(Offsets.EditControlsBrawler), "Silencer\0"); // cursed code; maybe i should've used js
}