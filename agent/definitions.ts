import { Offsets } from "./offsets.js";
import { Player } from "./player.js";

export const base = Module.getBaseAddress("libg.so");
export let createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["int", "int"]);
export let operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["int"]);
export let messageManagerReceiveMessage = new NativeFunction(base.add(Offsets.MessageManagerReceiveMessage), "int", ["pointer", "pointer"])
export let player = new Player();
export const possibleBotNames = ["loky", "sahar", "oskartocwel", "mroc", "croc", "KTR", "Flickz", "Interlastic", "Mold in my balls", "tomar753", "terpy", "Hallo", "free leon", "morticlowni", "ваня кек", "smw1", "Luna", "Hyra", "Juan Carlos", "Pituś", "Blast", "JordiTheCat", "TID_BOT_69", "Switly", "Tufa", "Trypix"];