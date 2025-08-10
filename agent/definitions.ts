import { Offsets } from "./offsets.js";
import { Player } from "./player.js";

export const base = Module.getBaseAddress("libg.so");

export const malloc = new NativeFunction(Module.getExportByName('libc.so', 'malloc'), 'pointer', ['uint']);

export const createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["int", "int"]);
export const operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["int"]);
export const messageManagerReceiveMessage = new NativeFunction(base.add(Offsets.MessageManagerReceiveMessage), "int", ["pointer", "pointer"]);
export const stringCtor = new NativeFunction(base.add(Offsets.StringConstructor), "pointer", ["pointer", "pointer"]);
export const showFloaterTextAtDefaultPos = new NativeFunction(base.add(Offsets.GUIShowFloaterTextAtDefaultPos), "int", ["pointer", "pointer", "float", "int"]);
export const gameGuiContainerAddGameButton = new NativeFunction(base.add(Offsets.GameGUIContainerAddGameButton), "pointer", ["pointer", "pointer", "int"]);
export const dropGuiContainerAddGameButton = new NativeFunction(base.add(Offsets.DropGUIContainerAddGameButton), "pointer", ["pointer", "pointer", "pointer"]);
export const customButtonSetButtonListener = new NativeFunction(base.add(Offsets.CustomButtonSetButtonListener), "pointer", ["pointer", "pointer"]);
export const homePageGetButtonByName = new NativeFunction(base.add(Offsets.HomePageGetButtonByName), "int", ["pointer", "pointer"]);
export const gameGuiContainerAddButton = new NativeFunction(base.add(Offsets.GUIContainerAddButton), "pointer", ["pointer", "pointer", "int"]);
export const stageAddChild = new NativeFunction(base.add(Offsets.StageAddChild), 'pointer', ['pointer', 'pointer']);
export const possibleBotNames = ["loky", "sahar", "oskartocwel", "mroc", "croc", "KTR", "Flickz", "Interlastic", "Mold in my balls", "tomar753", "terpy", "Hallo", "free leon", "morticlowni", "ваня кек", "smw1", "Luna", "Hyra", "Juan Carlos", "Pituś", "Blast", "JordiTheCat", "TID_BOT_69", "Switly", "Tufa", "Trypix"];
export const addFile = new NativeFunction(base.add(Offsets.ResourceListenerAddFile), "int", ['pointer', 'pointer', 'int', 'int', 'int', 'int', 'int']);
export const customButtonConstructor = new NativeFunction(base.add(Offsets.CustomButtonConstructor), 'int', []);
export const gameButtonConstructor = new NativeFunction(base.add(Offsets.GameButtonConstructor), 'pointer', ['pointer']);
export const resourceManagerGetMovieClip = new NativeFunction(base.add(Offsets.ResourceManagerGetMovieClip), 'pointer', ['pointer', 'pointer', 'bool']);
export const customButtonSetMovieClip = new NativeFunction(base.add(Offsets.CustomButtonSetMovieClip), 'pointer', ['pointer', 'pointer']);
export const MovieClipSetText = new NativeFunction(base.add(Offsets.MovieClipSetText), 'pointer', ['pointer', 'pointer']);
export const DisplayObjectSetSetXY = new NativeFunction(base.add(Offsets.DisplayObjectSetXY), 'pointer', ['pointer', 'int', 'int'])

export let player = new Player();

export const credits = `NBS Offline v2.2

Made by Natesworks 
Contact: contact@natesworks.com
Discord: dsc.gg/nbsoffline

💙THANKS TO💙

S.B:
- Making an amazing guide on reverse engineering/making Brawl Stars Offline (peterr.dev/re/brawl-stars-offline).
- Answering my questions when I didn't understand something.

xXCooBloyXx:
- Telling me how to get some of the required offsets for sendOfflineMessage.
- Teaching me how to view unobfuscate arxan obfuscated functions.

BSDS Client is used for killing arxan.
`