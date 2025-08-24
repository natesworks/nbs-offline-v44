import { addFile, base, config, customButtonSetMovieClip, displayObjectSetSetXY, gameButtonConstructor, gameButtonSetText, guiGetInstance, malloc, resourceManagerGetMovieClip, showFloaterTextAtDefaultPos, stageAddChild, stageRemoveChild } from "./definitions.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";
import { createStringObject, strPtr } from "./util.js";

let debugMenuOpened = false;
let debugMenuCreated = false;
let toggleButton: NativePointer;
let infiniteSuperButton: NativePointer;
let toggleBotsButton: NativePointer;
let debugMenu: NativePointer;

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
    infiniteSuperButton = spawnItem("debug_menu_item", "Infinite super", 1131, 100);
    toggleBotsButton = spawnItem("debug_menu_item", (config.disableBots ? "Enable" : "Disable") + " bots", 1131, 151);
}

export function hideDebugMenu() {
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
}

export function showDebugMenu() {
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
}

export function toggleDebugMenu() {
    if (!debugMenuCreated) {
        debugMenuCreated = true;
        createDebugMenu();
    }
    if (!debugMenuOpened) showDebugMenu()
    else { hideDebugMenu() }
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
    gameButtonSetText(toggleBotsButton, createStringObject((config.disableBots ? "Enable" : "Disable") + " bots"), 1);
}

Interceptor.attach(base.add(Offsets.CustomButtonButtonPressed),
    {
        onEnter(args) {
            if (args[0].toInt32() == toggleButton.toInt32()) toggleDebugMenu();
            else if (args[0].toInt32() == infiniteSuperButton.toInt32()) toggleInfiniteSuper();
            else if (args[0].toInt32() == toggleBotsButton.toInt32()) toggleBots();
        },
    });