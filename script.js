📦
618 /agent/index.js.map
327 /agent/index.js
795 /agent/offsets.js.map
2428 /agent/offsets.js
✄
{"version":3,"file":"index.js","sourceRoot":"/media/natesworks/Documents/nbsoffline/","sources":["agent/index.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,OAAO,EAAE,MAAM,cAAc,CAAC;AAEvC,MAAM,IAAI,GAAG,MAAM,CAAC,cAAc,CAAC,SAAS,CAAC,CAAC;AAE9C,WAAW,CAAC,MAAM,CAAC,IAAI,CAAC,GAAG,CAAC,OAAO,CAAC,sBAAsB,CAAC,EACvD;IACI,OAAO,CAAC,IAAI;QACR,IAAI,CAAC,CAAC,CAAC,CAAC,GAAG,CAAC,CAAC,CAAC,CAAC,WAAW,EAAE,CAAC,GAAG,CAAC,OAAO,CAAC,KAAK,CAAC,CAAC,QAAQ,CAAC,CAAC,CAAC,CAAC;QAC5D,IAAI,CAAC,CAAC,CAAC,CAAC,GAAG,CAAC,CAAC,CAAC,CAAC,WAAW,EAAE,CAAC,GAAG,CAAC,OAAO,CAAC,gBAAgB,CAAC,CAAC,OAAO,CAAC,CAAC,CAAC,CAAC;IAC1E,CAAC;CACJ,CAAC,CAAC"}
✄
import { Offsets } from "./offsets.js";
const base = Module.getBaseAddress("libg.so");
Interceptor.attach(base.add(Offsets.ServerConnectionUpdate), {
    onEnter(args) {
        args[0].add(4).readPointer().add(Offsets.State).writeInt(5);
        args[0].add(4).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
    }
});
✄
{"version":3,"file":"offsets.js","sourceRoot":"/media/natesworks/Documents/nbsoffline/","sources":["agent/offsets.ts"],"names":[],"mappings":"AAAA,MAAM,CAAN,IAAY,OAkCX;AAlCD,WAAY,OAAO;IAEf,+EAAiC,CAAA;IACjC,wEAA8B,CAAA;IAC9B,wCAAa,CAAA;IACb,6DAAoB,CAAA;IACpB,6DAAwB,CAAA;IACxB,2EAA+B,CAAA;IAC/B,iFAAkC,CAAA;IAClC,uEAA6B,CAAA;IAC7B,gFAAkC,CAAA;IAClC,yEAA8B,CAAA;IAC9B,0DAAuB,CAAA;IACvB,wDAAqB,CAAA;IACrB,8CAAgB,CAAA;IAChB,oFAAoC,CAAA;IACpC,0CAAc,CAAA;IACd,gEAA0B,CAAA;IAC1B,8DAAwB,CAAA;IACxB,2DAAuB,CAAA;IACvB,sDAAoB,CAAA;IACpB,qEAA4B,CAAA;IAC5B,2EAA+B,CAAA;IAC/B,8FAAwC,CAAA;IACxC,+DAAyB,CAAA;IACzB,6EAAgC,CAAA;IAChC,oFAAmC,CAAA;IACnC,uFAAqC,CAAA;IACrC,sEAA4B,CAAA;IAC5B,4CAAmB,CAAA;IACnB,mDAAmB,CAAA;IACnB,sEAA4B,CAAA;IAC5B,uEAA6B,CAAA;IAC7B,2FAAuC,CAAA;AAC3C,CAAC,EAlCW,OAAO,KAAP,OAAO,QAkClB"}
✄
export var Offsets;
(function (Offsets) {
    Offsets[Offsets["ServerConnectionUpdate"] = 6867748] = "ServerConnectionUpdate";
    Offsets[Offsets["ConnectingToServer"] = 21747432] = "ConnectingToServer";
    Offsets[Offsets["State"] = 16] = "State";
    Offsets[Offsets["HasConnectFailed"] = 4] = "HasConnectFailed";
    Offsets[Offsets["MessagingSend"] = 4215880] = "MessagingSend";
    Offsets[Offsets["MessagingSendMessage"] = 1501668] = "MessagingSendMessage";
    Offsets[Offsets["MessagingReceiveMessage"] = 1630032] = "MessagingReceiveMessage";
    Offsets[Offsets["GetMessageTypeName"] = 1630032] = "GetMessageTypeName";
    Offsets[Offsets["MessageManagerInstance"] = 23559104] = "MessageManagerInstance";
    Offsets[Offsets["CreateMessageByType"] = 7254536] = "CreateMessageByType";
    Offsets[Offsets["OperatorNew"] = 17454048] = "OperatorNew";
    Offsets[Offsets["GetMessageTye"] = 20] = "GetMessageTye";
    Offsets[Offsets["Destruct"] = 28] = "Destruct";
    Offsets[Offsets["LogicLaserMessageFactory"] = 17627190] = "LogicLaserMessageFactory";
    Offsets[Offsets["Decode"] = 12] = "Decode";
    Offsets[Offsets["PiranhaMessage"] = 17648226] = "PiranhaMessage";
    Offsets[Offsets["GetByteStream"] = 12669156] = "GetByteStream";
    Offsets[Offsets["GetByteArray"] = 9996684] = "GetByteArray";
    Offsets[Offsets["GetLength"] = 11100664] = "GetLength";
    Offsets[Offsets["HomePageStartGame"] = 9866336] = "HomePageStartGame";
    Offsets[Offsets["IsServerShuttingDown"] = 8054288] = "IsServerShuttingDown";
    Offsets[Offsets["ByteStreamWriteIntToByteArray"] = 13163808] = "ByteStreamWriteIntToByteArray";
    Offsets[Offsets["LoginOkMessage"] = 5575876] = "LoginOkMessage";
    Offsets[Offsets["HomePageButtonClicked"] = 4054648] = "HomePageButtonClicked";
    Offsets[Offsets["LogicConfDataGetIntValue"] = 12778376] = "LogicConfDataGetIntValue";
    Offsets[Offsets["LogicLocalizationGetString"] = 5298700] = "LogicLocalizationGetString";
    Offsets[Offsets["StringConstructor"] = 13271652] = "StringConstructor";
    Offsets[Offsets["Payload"] = 38] = "Payload";
    Offsets[Offsets["PayloadSize"] = 6] = "PayloadSize";
    Offsets[Offsets["LogicVersionIsDev"] = 12342476] = "LogicVersionIsDev";
    Offsets[Offsets["LogicVersionIsProd"] = 4890752] = "LogicVersionIsProd";
    Offsets[Offsets["LogicVersionIsDeveloperBuild"] = 7106744] = "LogicVersionIsDeveloperBuild";
})(Offsets || (Offsets = {}));