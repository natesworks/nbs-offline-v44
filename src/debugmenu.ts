import { addFile, base, customButtonSetMovieClip, displayObjectSetSetXY, gameButtonConstructor, malloc, movieClipSetText as movieClipSetText, resourceManagerGetMovieClip, stageAddChild } from "./definitions.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";
import { createStringObject, strPtr } from "./util.js";

export function addDebugFile() {
    const adder = Interceptor.attach(base.add(Offsets.ResourceListenerAddFile),
        {
            onEnter(args) {
                adder.detach();
                addFile(args[0], createStringObject("sc/debug.sc"), -1, -1, -1, -1, 0);
                Logger.debug("sc/debug.sc loaded");
            }
        })
}

export function spawnItem(item: string, text: string, x: number, y: number): NativePointer {
    let mem = malloc(1024);
    gameButtonConstructor(mem);
    let movieClip = resourceManagerGetMovieClip(strPtr("sc/debug.sc"), strPtr(item), 1);
    customButtonSetMovieClip(mem, movieClip);
    displayObjectSetSetXY(mem, x, y);
    movieClipSetText(mem, createStringObject(text));
    return mem;
}

export function createDebugButton() {
    Logger.debug("Creating debug button");
    let button = spawnItem("debug_button", "D", 30, 560);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), button);
}