import { base } from "./definitions";
import { Offsets } from "./offsets";

export function getScreenWidth(): number {
    return new NativeFunction(base.add(Offsets.ScreenGetWidth), "int", [])();
}

export function getScreenHeight(): number {
    return new NativeFunction(base.add(Offsets.ScreenGetHeight), "int", [])();
}

export function getScaleX(): number {
    return getScreenWidth() / 2400;
}

export function getScaleY(): number {
    return getScreenHeight() / 1080;
}