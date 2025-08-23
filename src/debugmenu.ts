import { addFile, base, config, customButtonSetButtonListener, customButtonSetMovieClip, displayObjectSetScaleX, displayObjectSetSetXY, gameButtonConstructor, gameButtonSetText, getTextFieldByName, guiGetInstance, malloc, movieClipSetText as movieClipSetText, resourceManagerGetMovieClip, showFloaterTextAtDefaultPos, stageAddChild, stageRemoveChild, textFieldConstructor, textFieldSetText } from "./definitions.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";
import { createStringObject, strPtr } from "./util.js";

let debugMenuOpened = false;
let debugMenuCreated = false;
let toggleButton: NativePointer;
let infiniteSuperButton: NativePointer;
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
    debugMenu = spawnItem("debug_menu", "Debug Menu", 1280, 0);
    infiniteSuperButton = spawnItem("debug_menu_item", "Infinite super", 1131, 100);
}

export function destroyDebugMenu() {
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
}

export function showDebugMenu() {
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
}

export function toggleDebugMenu() {
    if (!debugMenuCreated) {
        debugMenuCreated = true;
        createDebugMenu();
    }
    if (!debugMenuOpened) showDebugMenu()
    else { destroyDebugMenu() }
    debugMenuOpened = !debugMenuOpened;
}

export function toggleInfiniteSuper() {
    config.infiniteSuper = !config.infiniteSuper;
    let text = `Infinite super is now ${config.infiniteSuper ? "enabled" : "disabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
}

Interceptor.attach(base.add(Offsets.CustomButtonButtonPressed),
    {
        onEnter(args) {
            if (args[0].toInt32() == toggleButton.toInt32()) toggleDebugMenu();
            else if (args[0].toInt32() == infiniteSuperButton.toInt32()) toggleInfiniteSuper();
        },
    });