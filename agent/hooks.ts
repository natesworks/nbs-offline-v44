import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { base, messageManagerReceiveMessage } from "./definitions.js"
import { Messaging } from "./messaging.js";
import { LoginOkMessage } from "./packets/server/LoginOkMessage.js";
import { Player } from "./player.js";

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
        let type = PiranhaMessage.getMessageType(message);
        console.log("Type:", type)
        if (type == 10100) // client hello message
        {
            let player = new Player();
            messageManagerReceiveMessage(base.add(Offsets.MessageManagerInstance), Messaging.sendOfflineMessage(20104, LoginOkMessage.encode(player)));
        }
        PiranhaMessage.destroyMessage(message);
        return 0;
    }, "int", ["pointer", "pointer"])
);