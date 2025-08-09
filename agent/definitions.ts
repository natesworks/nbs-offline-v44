import { Offsets } from "./offsets.js";
import { Player } from "./player.js";

export const base = Module.getBaseAddress("libg.so");
export const createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["int", "int"]);
export const operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["int"]);
export const messageManagerReceiveMessage = new NativeFunction(base.add(Offsets.MessageManagerReceiveMessage), "int", ["pointer", "pointer"])
export const stringCtor = new NativeFunction(base.add(Offsets.StringConstructor), "pointer", ["pointer", "pointer"])
export const showFloaterTextAtDefaultPos = new NativeFunction(base.add(Offsets.GUIShowFloaterTextAtDefaultPos), "int", ["pointer", "pointer", "float", "int"])
export const gameGuiContainerAddGameButton = new NativeFunction(base.add(Offsets.GameGUIContainerAddGameButton), "int", ["pointer", "pointer", "pointer"])
export let player = new Player();
export const possibleBotNames = ["loky", "sahar", "oskartocwel", "mroc", "croc", "KTR", "Flickz", "Interlastic", "Mold in my balls", "tomar753", "terpy", "Hallo", "free leon", "morticlowni", "ваня кек", "smw1", "Luna", "Hyra", "Juan Carlos", "Pituś", "Blast", "JordiTheCat", "TID_BOT_69", "Switly", "Tufa", "Trypix"];
export const credits = `NBS Offline v2.2

Made by Natesworks 
Contact: contact@natesworks.com
Discord: dsc.gg/nbsoffline

\u{1F499}THANKS TO\u{1F499}

S.B:
- Making an amazing guide on reverse engineering/making Brawl Stars Offline (peterr.dev/re/brawl-stars-offline).
- Answering my questions when I didn't understand something.

xXCooBloyXx:
- Telling me how to get some of the required offsets for sendOfflineMessage.
- Teaching me how to view unobfuscate arxan obfuscated functions.

BSDS Client is used for killing arxan.
`