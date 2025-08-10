import { addFile, base, customButtonSetMovieClip, DisplayObjectSetSetXY, gameButtonConstructor, malloc, MovieClipSetText as movieClipSetText, resourceManagerGetMovieClip, stageAddChild } from "./definitions.js";
import { Offsets } from "./offsets.js";
import { createStringObject, strPtr } from "./util.js";

export function addDebugFile() {
    const adder = Interceptor.attach(base.add(Offsets.ResourceListenerAddFile),
        {
            onEnter(args) {
                adder.detach();
                addFile(args[0], createStringObject("sc/debug.sc"), -1, -1, -1, -1, 0);
                console.log("sc/debug.sc loaded");
            }
        })
}

export function spawnItem(item: string, text: string, x: number, y: number): NativePointer {
    let mem = malloc(1024);
    gameButtonConstructor(mem);
    let itemPtr = strPtr(item);
    let debugSCPtr = strPtr("sc/debug.sc");
    let movieClip = resourceManagerGetMovieClip(debugSCPtr, itemPtr, 1);
    customButtonSetMovieClip(mem, movieClip);
    movieClipSetText(mem, createStringObject(text));
    DisplayObjectSetSetXY(mem, x, y);
    return mem;
}

export function createDebugButton() {
    let button = spawnItem("debug_button", "D", 30, 560);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), button);
}