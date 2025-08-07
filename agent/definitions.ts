import { Offsets } from "./offsets.js";

export const base = Module.getBaseAddress("libg.so");
export let createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["int", "int"]);
export let operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["int"]);
export let messageManagerReceiveMessage = new NativeFunction(base.add(Offsets.MessageManagerReceiveMessage), "int", ["pointer", "pointer"])