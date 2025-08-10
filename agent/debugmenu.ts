import { addFile, base, customButtonSetMovieClip, gameButtonConstructor, malloc, MovieClipSetText as movieClipSetText, resourceManagerGetMovieClip, stageAddChild } from "./definitions.js";
import { Offsets } from "./offsets.js";
import { createStringObject, strPtr } from "./util.js";

let debugSCPtr: NativePointer;

export function addDebugFile() {
    const adder = Interceptor.attach(base.add(Offsets.ResourceListenerAddFile),
        {
            onEnter(args) {
                adder.detach();
                debugSCPtr = Memory.alloc(Process.pointerSize)
                debugSCPtr.writePointer(base.add(Offsets.DebugSC))
                addFile(args[0], debugSCPtr, -1, -1, -1, -1, 0);
                console.log("sc/debug.sc loaded");
            }
        })
}

export function spawnItem(item: string, text: string, x: number, y: number) : NativePointer {
    let mem = malloc(1024);
    gameButtonConstructor(mem);
    let movieClip = resourceManagerGetMovieClip(debugSCPtr, Memory.allocUtf8String(item), 1);
    customButtonSetMovieClip(mem, movieClip);
    movieClipSetText(mem, createStringObject(text));
    return mem;
}

export function createDebugButton() {
    let button = spawnItem("debug_button", "D", 30, 560);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), button);
}