import { addFile, base, malloc } from "./definitions.js";
import { Offsets } from "./offsets.js";
import { strPtr } from "./util.js";

function addDebugFile() {
    const adder = Interceptor.attach(base.add(Offsets.ResourceListenerAddFile),
        {
            onEnter(args) {
                adder.detach();
                let str = strPtr("sc/debug.sc");
                const debugSCPtr = Memory.alloc(Process.pointerSize)
                debugSCPtr.writePointer(base.add(Offsets.DebugSC))
                addFile(args[0], debugSCPtr, -1, -1, -1, -1, 0);
                console.log("sc/debug.sc loaded");
            }
        })
}

function createDebugButton() {
    let button = malloc(700);

}

export function setup() {
    addDebugFile();
}