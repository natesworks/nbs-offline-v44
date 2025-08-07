import { Offsets } from "./offsets.js";

const base = Module.getBaseAddress("libg.so");

Interceptor.attach(base.add(Offsets.ServerConnectionUpdate),
    {
        onEnter(args) {
            args[0].add(4).readPointer().add(Offsets.State).writeInt(5);
            args[0].add(4).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
        }
    });