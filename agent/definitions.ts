import { Config, readConfig } from "./config.js";
import { Offsets } from "./offsets.js";
import { Player } from "./player.js";
import { copyFile, getLibraryDir, openFile, readFile } from "./util.js";

export const base = Module.getBaseAddress("libg.so");

export const malloc = new NativeFunction(Module.getExportByName('libc.so', 'malloc'), 'pointer', ['uint']);
export const open = new NativeFunction(Module.getExportByName('libc.so', "open"), "int", ["pointer", "int", "int"]);
export const read = new NativeFunction(Module.getExportByName('libc.so', "read"), "int", ["int", "pointer", "int"]);
export const write = new NativeFunction(Module.getExportByName('libc.so', "write"), "int", ["int", "pointer", "int"]);
export const close = new NativeFunction(Module.getExportByName('libc.so', "close"), "int", ["int"]);
export const O_RDONLY = 0;
export const O_WRONLY = 1;
export const O_RDWR = 2;
export const O_CREAT = 64;
export const O_TRUNC = 512;
export const O_APPEND = 1024;

export const android_log_write = new NativeFunction(
    Module.findExportByName("liblog.so", "__android_log_write")!,
    'int',
    ['int', 'pointer', 'pointer']
);

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
export const movieClipSetText = new NativeFunction(base.add(Offsets.MovieClipSetText), 'pointer', ['pointer', 'pointer']);
export const displayObjectSetSetXY = new NativeFunction(base.add(Offsets.DisplayObjectSetXY), 'pointer', ['pointer', 'int', 'int']);
export const logicCharacterServerChargeUlti = new NativeFunction(base.add(Offsets.DisplayObjectSetXY), 'int', ['int', 'int', 'int', 'int', 'int']);
export const radioButtonCreate = new NativeFunction(base.add(Offsets.RadioButtonCreateButton), 'pointer', ['pointer', 'pointer', 'pointer']);
export const radioButtonCreate2 = new NativeFunction(base.add(Offsets.RadioButtonCreateButton), 'pointer', ['pointer', 'pointer', 'pointer']);
export const setRadioButtonState = new NativeFunction(base.add(Offsets.RadioButtonSetRadioButtonState), 'int', ['pointer', 'pointer', 'pointer']);
export const getMovieClipByName = new NativeFunction(base.add(Offsets.GetMovieClipByName), 'int', ['pointer', 'pointer']);
export const movieClipConstructor = new NativeFunction(base.add(Offsets.MovieClipConstructor), 'pointer', ['pointer']);

export let player = new Player();
export let config: Config;
export let pkg: string;
export let logFile: number;
export let libPath: string;
export let configPath: string;

export function load() {
    pkg = readFile(openFile("/proc/self/cmdline")).split("\0")[0]
    logFile = openFile(`/storage/emulated/0/Android/data/${pkg}/log.txt`, true);
    libPath = getLibraryDir();
    configPath = `/storage/emulated/0/Android/data/${pkg}/config.json`;
    copyFile(libPath + "/libNBS.c.so", configPath, false);
    config = readConfig();
}

export const brawlPassButtonIsDisabled = 37;
export const shopIsDisabled = 5;
export const friendlyGameLevelRequirement = 3;
export const hiddenButtons = ["button_country", "button_faq", "button_language", "button_sc_id", "button_terms", "button_privacy", "button_parentsguide", "button_thirdparty", "button_api", "button_google_connect", "button_kakao_connect", "button_line_connect", "button_privacy_settings", "button_birthday", "button_edit_controls"];
export const hiddenText = ["LANGUAGE", "LOCATION", "SUPERCELL ID", "PLAY WITH FRIENDS", "Google Play Sign-In", "BLOCK FRIEND REQUESTS", "SOCIAL"];

export const credits = `NBS Offline v2.3.1

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
