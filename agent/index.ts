import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { base } from "./definitions.js"

Interceptor.attach(base.add(Offsets.ServerConnectionUpdate),
    {
        onEnter(args) {
            args[0].add(4).readPointer().add(Offsets.State).writeInt(5);
            args[0].add(4).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
        }
    });

Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage),
    {
        onLeave(retval) {
            retval.replace(ptr(1));
        }
    });

Interceptor.replace(
    base.add(Offsets.MessagingSend),
    new NativeCallback(function (self, message) {
        PiranhaMessage.destroyMessage(message);
        return 0;
    }, "int", ["pointer", "pointer"])
);