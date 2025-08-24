import { Config, readConfig, tryLoadDefaultConfig } from "./config.js";
import { openFile, readFile } from "./fs.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";
import { Player } from "./player.js";
import { UpdaterConfig } from "./updaterconfig.js";
import { readUpdaterConfig } from "./updaterutil.js";
import { getLibraryDir } from "./util.js";

export const base = Module.getBaseAddress("libg.so");

export const errno = new NativeFunction(Module.getExportByName("libc.so", "__errno"), "pointer", []);

export const malloc = new NativeFunction(Module.getExportByName("libc.so", "malloc"), "pointer", ["uint"]);
export const open = new NativeFunction(Module.getExportByName("libc.so", "open"), "int", ["pointer", "int", "int"]);
export const read = new NativeFunction(Module.getExportByName("libc.so", "read"), "int", ["int", "pointer", "int"]);
export const write = new NativeFunction(Module.getExportByName("libc.so", "write"), "int", ["int", "pointer", "int"]);
export const close = new NativeFunction(Module.getExportByName("libc.so", "close"), "int", ["int"]);
export const mkdir = new NativeFunction(Module.getExportByName("libc.so", "mkdir"), "int", ["pointer", "uint32"]); // mode_t is a typedef to uint
export const O_RDONLY = 0;
export const O_WRONLY = 1;
export const O_RDWR = 2;
export const O_CREAT = 64;
export const O_TRUNC = 512;
export const O_APPEND = 1024;
export const ENOENT = 2;
export const EEXIST = 17;
// int mkdir(const char *pathname, mode_t mode)

export const android_log_write = new NativeFunction(
    Module.findExportByName("liblog.so", "__android_log_write")!,
    "int",
    ["int", "pointer", "pointer"]
);

export const createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["int", "int"]);
export const operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["int"]);
export const messageManagerReceiveMessage = new NativeFunction(base.add(Offsets.MessageManagerReceiveMessage), "int", ["pointer", "pointer"]);
export const stringCtor = new NativeFunction(base.add(Offsets.StringConstructor), "pointer", ["pointer", "pointer"]);
export const showFloaterTextAtDefaultPos = new NativeFunction(base.add(Offsets.GUIShowFloaterTextAtDefaultPos), "int", ["pointer", "pointer", "float", "int"]);
export const gameGuiContainerAddGameButton = new NativeFunction(base.add(Offsets.DropGUIContainerAddGameButton), "pointer", ["pointer", "pointer", "int"]);
export const dropGuiContainerAddGameButton = new NativeFunction(base.add(Offsets.DropGUIContainerAddGameButton2), "pointer", ["pointer", "pointer", "pointer"]);
export const customButtonSetButtonListener = new NativeFunction(base.add(Offsets.CustomButtonSetButtonListener), "pointer", ["pointer", "pointer"]);
export const homePageGetButtonByName = new NativeFunction(base.add(Offsets.HomePageGetButtonByName), "int", ["pointer", "pointer"]);
export const gameGuiContainerAddButton = new NativeFunction(base.add(Offsets.GUIContainerAddButton), "pointer", ["pointer", "pointer", "int"]);
export const stageAddChild = new NativeFunction(base.add(Offsets.StageAddChild), "pointer", ["pointer", "pointer"]);
export const possibleBotNames = ["loky", "sahar", "mroc", "croc", "KTR", "Flickz", "Interlastic", "Mold in my balls", "tomar753", "terpy", "Hallo", "free leon", "ваня кек", "smw1", "Luna", "Hyra", "Juan Carlos", "Pituś", "Blast", "JordiTheCat", "TID_BOT_69", "Switly", "Tufa", "Trypix"];
export const addFile = new NativeFunction(base.add(Offsets.ResourceListenerAddFile), "int", ["pointer", "pointer", "int", "int", "int", "int", "int"]);
export const customButtonConstructor = new NativeFunction(base.add(Offsets.CustomButtonConstructor), "int", []);
export const gameButtonConstructor = new NativeFunction(base.add(Offsets.GameButtonConstructor), "pointer", ["pointer"]);
export const resourceManagerGetMovieClip = new NativeFunction(base.add(Offsets.ResourceManagerGetMovieClip), "pointer", ["pointer", "pointer", "bool"]);
export const customButtonSetMovieClip = new NativeFunction(base.add(Offsets.CustomButtonSetMovieClip), "pointer", ["pointer", "pointer"]);
export const movieClipSetText = new NativeFunction(base.add(Offsets.MovieClipSetText), "pointer", ["pointer", "pointer", "pointer"]);
export const displayObjectSetSetXY = new NativeFunction(base.add(Offsets.DisplayObjectSetXY), "pointer", ["pointer", "float", "float"]);
export const displayObjectSetX = new NativeFunction(base.add(Offsets.DisplayObjectSetX), "pointer", ["pointer", "float"]);
export const displayObjectSetY = new NativeFunction(base.add(Offsets.DisplayObjectSetY), "pointer", ["pointer", "float"]);
export const logicCharacterServerChargeUlti = new NativeFunction(base.add(Offsets.DisplayObjectSetXY), "int", ["int", "int", "int", "int", "int"]);
export const radioButtonCreate = new NativeFunction(base.add(Offsets.RadioButtonCreateButton), "pointer", ["pointer", "pointer", "pointer"]);
export const radioButtonCreate2 = new NativeFunction(base.add(Offsets.RadioButtonCreateButton), "pointer", ["pointer", "pointer", "pointer"]);
export const setRadioButtonState = new NativeFunction(base.add(Offsets.RadioButtonSetRadioButtonState), "int", ["pointer", "pointer", "pointer"]);
export const getMovieClipByName = new NativeFunction(base.add(Offsets.GetMovieClipByName), "int", ["pointer", "pointer"]);
export const movieClipConstructor = new NativeFunction(base.add(Offsets.MovieClipConstructor), "pointer", ["pointer"]);
export const gameMainShowNativeDialog = new NativeFunction(base.add(Offsets.GameMainShowNativeDialog), "pointer", ["pointer", "uint", "uint", "pointer", "pointer", "pointer"]);
export const messagingSend = new NativeFunction(base.add(Offsets.MessagingSend), "int", ["pointer", "pointer"]);
export const applicationOpenURL = new NativeFunction(base.add(Offsets.ApplicationOpenURL), "pointer", ["pointer"]);
export const settingsScreenOpenFAQ = new NativeFunction(base.add(Offsets.SettingsScreenOpenFAQ), "pointer", ["pointer"]);
export const textFieldSetText = new NativeFunction(base.add(Offsets.TextFieldSetText), "int", ["pointer", "pointer"])
export const displayObjectGetScaleX = new NativeFunction(base.add(Offsets.DisplayObjectGetScaleX), "float", ["pointer"]);
export const displayObjectGetScaleY = new NativeFunction(base.add(Offsets.DisplayObjectGetScaleY), "float", ["pointer"]);
export const displayObjectSetScaleX = new NativeFunction(base.add(Offsets.DisplayObjectSetScaleX), "pointer", ["pointer", "float"]);
export const displayObjectSetScaleY = new NativeFunction(base.add(Offsets.DisplayObjectSetScaleY), "pointer", ["pointer", "float"]);
export const guiGetInstance = new NativeFunction(base.add(Offsets.GUIGetInstance), "pointer", []);
export const gameButtonSetText = new NativeFunction(base.add(Offsets.GameButtonSetText), "int", ["pointer", "pointer", "bool"]);
export const getTextFieldByName = new NativeFunction(base.add(Offsets.GetTextFieldByName), "pointer", ["pointer", "pointer"]);
export const textFieldConstructor = new NativeFunction(base.add(Offsets.TextFieldConstructor), "pointer", ["pointer"]);
export const stageRemoveChild = new NativeFunction(base.add(Offsets.StageRemoveChild), "pointer", ["pointer", "pointer"]);
export const logicCharacterServerTickAI = new NativeFunction(base.add(Offsets.LogicCharacterServerTickAI), "pointer", ["pointer"]);
export const displayObjectSetScale = new NativeFunction(base.add(Offsets.DisplayObjectSetScale), "pointer", ["pointer", "float"]);
export const reloadGameInternal = new NativeFunction(base.add(Offsets.GameMainReloadGameInternal), "pointer", ["pointer"]);

export const branchButtonYPos = -50;
export const stableButtonXPos = -280;
export const devTextFieldPos = [-88.5, -26];
export const creditPos = [282, -156.5]
export const tosURL = "http://www.supercell.com/en/privacy-policy/";
export const privacyURL = "http://supercell.com/en/terms-of-service/"

export let player = new Player();
export let config: Config;
export let updaterConfig: UpdaterConfig | null = null;
export let pkg: string;
export let logFile: number;
export let libPath: string;
export let configPath: string;
export let defaultConfigPath: string;
export let dataDirectory: string;
export let packetDumpsDirectory: string;
export let updaterConfigPath: string;
export let version = "v2.5";
export let stableTextField: NativePointer;
export let betaTextField: NativePointer;
export let devTextField: NativePointer;

export function load() {
    if (ISDEV)
        version += ` (${COMMIT})`
    pkg = readFile(openFile("/proc/self/cmdline")).split("\0")[0];
    dataDirectory = `/storage/emulated/0/Android/data/${pkg}/files`;
    packetDumpsDirectory = `${dataDirectory}/packetdumps`
    logFile = openFile(`${dataDirectory}/log.txt`, true);
    if (logFile < 0) {
        throw new Error("Failed to open log file"); // cant check if u have log to file enabled at this point sry
    }
    libPath = getLibraryDir();
    defaultConfigPath = libPath + "/libNBS.c.so";
    configPath = `${dataDirectory}/config.json`;
    tryLoadDefaultConfig();
    config = readConfig();
    updaterConfigPath = `${dataDirectory}/updater.json`;
    let updaterConfigFile = openFile(updaterConfigPath);
    if (updaterConfigFile < 0) {
        Logger.warn("Updater configuration file doesn't exist");

    }
    else {
        close(updaterConfigFile);
        updaterConfigFile = openFile(updaterConfigPath, true);
        updaterConfig = readUpdaterConfig(updaterConfigFile);
        close(updaterConfigFile);
    }
}

export function setStableTextField(ptr: NativePointer) {
    stableTextField = ptr;
}

export function setBetaTextField(ptr: NativePointer) {
    betaTextField = ptr;
}

export function setDevTextField(ptr: NativePointer) {
    devTextField = ptr;
}

export const brawlPassButtonIsDisabled = 37;
export const shopIsDisabled = 5;
export const friendlyGameLevelRequirement = 3;

export const hiddenButtons = ["button_country", "button_edit_controls", "button_language", "button_sc_id", "button_parentsguide", "button_thirdparty", "button_api", "button_google_connect", "button_kakao_connect", "button_line_connect", "button_privacy_settings", "button_birthday", "button_privacy"];
export const hiddenText = ["LANGUAGE", "PLAY WITH FRIENDS", "Google Play Sign-In", "BLOCK FRIEND REQUESTS", "SOCIAL", "LOCATION"];
export const branchButtons = ["button_faq", "button_terms", "button_privacy", "button_allow_friend_requests"]

export const credits = `NBS Offline ${version}

Made by Natesworks 
Discord: dsc.gg/nbsoffline
Telegram: t.me/nbsoffline

THANKS TO:

S.B:
- Making an amazing guide on reverse engineering/making Brawl Stars Offline (peterr.dev/re/brawl-stars-offline).
- Answering my questions when I didn"t understand something.

xXCooBloyXx:
- Telling me how to get some of the required offsets for sendOfflineMessage.
- Teaching me how to view unobfuscate arxan obfuscated functions.

BSDS:
- Making a script to kill Arxan
- OwnHomeDataMessage and PlayerProfileMessage structure
`
