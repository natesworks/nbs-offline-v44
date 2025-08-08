import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { base, player } from "./definitions.js";
import { Messaging } from "./messaging.js";
import { LoginOkMessage } from "./packets/server/LoginOkMessage.js";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage.js";
import { LobbyInfoMessage } from "./packets/server/LobbyInfoMessage.js";
import { getBotNames } from "./util.js";

let botNames: string[] = [];

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

Interceptor.attach(base.add(Offsets.HomePageStartGame),
    {
        onEnter(args) {
            args[3] = ptr(3);
            botNames = getBotNames();
        }
    });

Interceptor.attach(base.add(Offsets.LogicLocalizationGetString),
    {
        onEnter(args) {
            this.tid = args[0].readCString();
            if (this.tid && this.tid.startsWith("TID_BOT_")) {
                let botIndex = parseInt(this.tid.slice(8), 10) - 1;
                args[0].writeUtf8String(botNames[botIndex]);
            }
        }
    });

Interceptor.attach(base.add(Offsets.LogicConfDataGetIntValue),
    {
        onEnter(args) {
            if (args[1].equals(ptr(5)) || args[1].equals(ptr(37)))
                this.retval = ptr(1);
        },

        onLeave(retval) {
            if (this.retval !== undefined)
                retval.replace(this.retval);
        }
    });

Interceptor.replace(
    base.add(Offsets.MessagingSend),
    new NativeCallback(function (self, message) {
        let type = PiranhaMessage.getMessageType(message);

        Messaging.sendOfflineMessage(23457, LobbyInfoMessage.encode(player));

        if (type == 10108)
            return 0;

        console.log("Type:", type);

        if (type == 10100) { // ClientHelloMessage
            Messaging.sendOfflineMessage(20104, LoginOkMessage.encode(player));
            Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
        }
        else if (type == 14109) { // GoHomeFromOfflinePracticeMessage
            Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
        }

        PiranhaMessage.destroyMessage(message);

        return 0;
    }, "int", ["pointer", "pointer"])
);
