import { addFile, base, config, customButtonSetMovieClip, displayObjectSetScale, displayObjectSetSetXY, gameButtonConstructor, gameButtonSetText, guiGetInstance, malloc, movieClipSetText, reloadGameInternal, resourceManagerGetMovieClip, showFloaterTextAtDefaultPos, stageAddChild, stageRemoveChild } from "./definitions.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";
import { createStringObject, strPtr } from "./util.js";

let debugMenu: NativePointer;
let debugMenuTitle: NativePointer;
let debugMenuDescription: NativePointer;

let debugMenuOpened = false;

let generalCategory: NativePointer | null = null;
let accountCategory: NativePointer | null = null;
let battleCategory: NativePointer | null = null;

let generalCategoryOpened = false;
let accountCategoryOpened = false;
let battleCategoryOpened = false;

let toggleButton: NativePointer;
let reloadGameButton: NativePointer | null = null;
let infiniteSuperButton: NativePointer | null = null;
let toggleBotsButton: NativePointer | null = null;
let toggleArtTestButton: NativePointer | null = null;

const firstButton = 100;
const buttonOffset = 55;

const generalCategoryButtonCount = 1;
const accountCategoryButtonCount = 0;
const battleCategoryButtonCount = 3;

function getGeneralCategoryPosition() {
    return firstButton;
}

function getAccountCategoryPosition() {
    let pos = firstButton + buttonOffset;
    if (generalCategoryOpened)
        pos += buttonOffset * generalCategoryButtonCount;
    return pos;
}

function getBattleCategoryPositon() {
    let pos = firstButton + 2 * buttonOffset;
    if (generalCategoryOpened)
        pos += buttonOffset * generalCategoryButtonCount;
    if (accountCategoryOpened)
        pos += buttonOffset * accountCategoryButtonCount;
    return pos;
}

export function addDebugFile() {
    const adder = Interceptor.attach(base.add(Offsets.ResourceListenerAddFile),
        {
            onEnter(args) {
                adder.detach();
                addFile(args[0], createStringObject("sc/debug.sc"), -1, -1, -1, -1, 0);
                Logger.debug("sc/debug.sc loaded");
            }
        });
}

export function spawnItem(item: string, text: string, x: number, y: number): NativePointer {
    let mem = malloc(1024);
    gameButtonConstructor(mem);
    let movieClip = resourceManagerGetMovieClip(strPtr("sc/debug.sc"), strPtr(item), 1);
    customButtonSetMovieClip(mem, movieClip);
    displayObjectSetSetXY(mem, x, y);
    gameButtonSetText(mem, createStringObject(text), 1);
    return mem;
}

export function createDebugButton() {
    Logger.debug("Creating debug button");
    toggleButton = spawnItem("debug_button", "D", 20, 560);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleButton);
}

export function createDebugMenu() {
    Logger.debug("Creating debug menu");
    debugMenu = spawnItem("debug_menu", "Debug Menu", 1280, 0);

    debugMenuTitle = spawnItem("debug_menu_text", "<c62a0ea>NBS Offline</c>", 1075, 0);
    displayObjectSetScale(debugMenuTitle, 1.5);
    debugMenuDescription = spawnItem("debug_menu_text", "<c62a0ea>dsc.gg/nbsoffline</c>", 1075, 20);

    generalCategory = spawnItem("debug_menu_category", (generalCategoryOpened ? "- " : "+ ") + "General", 1131, getGeneralCategoryPosition());
    accountCategory = spawnItem("debug_menu_category", (accountCategoryOpened ? "- " : "+ ") + "Account", 1131, getAccountCategoryPosition());
    battleCategory = spawnItem("debug_menu_category", (battleCategoryOpened ? "- " : "+ ") + "Battle", 1131, getBattleCategoryPositon());

    if (generalCategoryOpened) {
        reloadGameButton = spawnItem("debug_menu_item", "Reload Game", 1131, getGeneralCategoryPosition() + buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
    }

    if (accountCategoryOpened) {

    }

    if (battleCategoryOpened) {
        infiniteSuperButton = spawnItem("debug_menu_item", "Infinite Super", 1131, getBattleCategoryPositon() + buttonOffset);
        toggleBotsButton = spawnItem("debug_menu_item", (config.disableBots ? "Enable" : "Disable") + " Bots", 1131, getBattleCategoryPositon() + 2 * buttonOffset);
        toggleArtTestButton = spawnItem("debug_menu_item", (config.artTest ? "Disable" : "Enable") + " Art Test", 1131, getBattleCategoryPositon() + 3 * buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
    }

    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);

    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenuTitle);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenuDescription);

    stageAddChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);
}

export function updateDebugMenu() {
    Logger.debug("Updating debug menu");
    
    if (generalCategory) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    }
    if (accountCategory) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);
    }
    if (battleCategory) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    }

    if (reloadGameButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
        reloadGameButton = null;
    }

    if (infiniteSuperButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        infiniteSuperButton = null;
    }
    if (toggleBotsButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        toggleBotsButton = null;
    }
    if (toggleArtTestButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
        toggleArtTestButton = null;
    }

    generalCategory = spawnItem("debug_menu_category", (generalCategoryOpened ? "- " : "+ ") + "General", 1131, getGeneralCategoryPosition());
    accountCategory = spawnItem("debug_menu_category", (accountCategoryOpened ? "- " : "+ ") + "Account", 1131, getAccountCategoryPosition());
    battleCategory = spawnItem("debug_menu_category", (battleCategoryOpened ? "- " : "+ ") + "Battle", 1131, getBattleCategoryPositon());

    if (generalCategoryOpened) {
        reloadGameButton = spawnItem("debug_menu_item", "Reload Game", 1131, getGeneralCategoryPosition() + buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
    }

    if (accountCategoryOpened) {

    }

    if (battleCategoryOpened) {
        infiniteSuperButton = spawnItem("debug_menu_item", "Infinite Super", 1131, getBattleCategoryPositon() + buttonOffset);
        toggleBotsButton = spawnItem("debug_menu_item", (config.disableBots ? "Enable" : "Disable") + " Bots", 1131, getBattleCategoryPositon() + 2 * buttonOffset);
        toggleArtTestButton = spawnItem("debug_menu_item", (config.artTest ? "Disable" : "Enable") + " Art Test", 1131, getBattleCategoryPositon() + 3 * buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
    }

    stageAddChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);
}

export function hideDebugMenu() {
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);

    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenuTitle);
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenuDescription);

    if (generalCategory) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    if (battleCategory) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    if (accountCategory) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);

    if (generalCategoryOpened && reloadGameButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
    }

    if (accountCategoryOpened) {

    }

    if (battleCategoryOpened) {
        if (infiniteSuperButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        if (toggleBotsButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        if (toggleArtTestButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
    }
}

export function toggleDebugMenu() {
    if (!debugMenuOpened) createDebugMenu()
    else hideDebugMenu()
    debugMenuOpened = !debugMenuOpened;
}

export function toggleInfiniteSuper() {
    config.infiniteSuper = !config.infiniteSuper;
    let text = `Infinite super is now ${config.infiniteSuper ? "enabled" : "disabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
}

export function toggleBots() {
    config.disableBots = !config.disableBots;
    let text = `Bots are now ${config.disableBots ? "disabled" : "enabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
    if (toggleBotsButton) {
        gameButtonSetText(toggleBotsButton, createStringObject((config.disableBots ? "Enable" : "Disable") + " Bots"), 1);
    }
}

export function toggleArtTest() {
    config.artTest = !config.artTest;
    let text = `Art test is now ${config.artTest ? "enabled" : "disabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
    if (toggleArtTestButton) {
        gameButtonSetText(toggleArtTestButton, createStringObject((config.artTest ? "Disable" : "Enable") + " Art Test"), 1);
    }
    (Memory as any).writeU8(base.add(Offsets.ArtTest), Number(config.artTest));
}

Interceptor.attach(base.add(Offsets.CustomButtonButtonPressed),
    {
        onEnter(args) {
            if (toggleButton && args[0].toInt32() == toggleButton.toInt32()) toggleDebugMenu();
            else if (generalCategory && args[0].toInt32() == generalCategory.toInt32()) generalCategoryOpened = !generalCategoryOpened;
            else if (accountCategory && args[0].toInt32() == accountCategory.toInt32()) accountCategoryOpened = !accountCategoryOpened;
            else if (battleCategory && args[0].toInt32() == battleCategory.toInt32()) battleCategoryOpened = !battleCategoryOpened;
            else if (infiniteSuperButton && args[0].toInt32() == infiniteSuperButton.toInt32()) toggleInfiniteSuper();
            else if (toggleBotsButton && args[0].toInt32() == toggleBotsButton.toInt32()) toggleBots();
            else if (toggleArtTestButton && args[0].toInt32() == toggleArtTestButton.toInt32()) toggleArtTest();
            else if (reloadGameButton && args[0].toInt32() == reloadGameButton.toInt32()) reloadGameInternal(base.add(Offsets.GameMainInstance));

            if (debugMenuOpened) updateDebugMenu();
        },
    });