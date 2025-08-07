import { Offsets } from "./offsets.js";
import { base, createMessageByType, messageManagerReceiveMessage, operator_new } from "./definitions.js";
import { PiranhaMessage } from "./piranhamessage.js";

export class Messaging {
    static sendOfflineMessage(id: number, payload: Uint8Array) {
        let version = id == 20104 ? 1 : 0;
        let message = createMessageByType(0, id);
        message.add(Offsets.Version).writeS32(version);
        message.add(PiranhaMessage.getByteStream(message).add(Offsets.PayloadSize)).writeS32(payload.length);
        if (payload.length > 0) {
            let payloadPtr = operator_new(payload.length).writeByteArray(Array.from(payload));
            PiranhaMessage.getByteStream(message).add(Offsets.PayloadPtr).writePointer(payloadPtr);
        }
        let decode = new NativeFunction(
            message
                .readPointer()
                .add(Offsets.Decode)
                .readPointer(),
            "void",
            ["pointer"]
        );
        decode(message);
        messageManagerReceiveMessage(base.add(Offsets.MessageManagerInstance), message);
    }
}