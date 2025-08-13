import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { base, credits, customButtonSetButtonListener, dropGuiContainerAddGameButton as dropGUIContainerAddGameButton, gameGuiContainerAddButton, gameGuiContainerAddGameButton, homePageGetButtonByName, player, showFloaterTextAtDefaultPos, stringCtor } from "./definitions.js";
import { Messaging } from "./messaging.js";
import { LoginOkMessage } from "./packets/server/LoginOkMessage.js";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage.js";
import { LobbyInfoMessage } from "./packets/server/LobbyInfoMessage.js";
import { createStringObject, getBotNames, decodeString } from "./util.js";
import { PlayerProfileMessage } from "./packets/server/PlayerProfileMessage.js";
import { createDebugButton } from "./debugmenu.js";

let botNames: string[] = [];
let homePageInstance: NativePointerValue;

export function installHooks() {

    Interceptor.attach(base.add(Offsets.ServerConnectionUpdate),
        {
            onEnter: function (args) {
                args[0].add(Process.pointerSize).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
                args[0].add(Process.pointerSize).readPointer().add(Offsets.State).writeInt(5);
            }
        });

    Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage),
        {
            onLeave: function (retval) {
                retval.replace(ptr(1));
            }
        });

    Interceptor.attach(base.add(Offsets.HomePageStartGame),
        {
            onEnter: function (args) {
                args[3] = ptr(3);
                botNames = getBotNames();
            }
        });

    /* to hide the debug ui; on newer versions instead just replace retval of LogicVersion::isDebugUIAvailable */
    Interceptor.attach(base.add(Offsets.CombatHUDButtonClicked),
        {
            onEnter: function () {
                this.isDevBuildHook = Interceptor.attach(base.add(Offsets.LogicVersionIsDeveloperBuild),
                    {
                        onLeave: function (retval) {
                            retval.replace(ptr(0));
                        }
                    });
            },
            onLeave: function () {
                this.isDevBuildHook.detach();
            }
        });

    Interceptor.attach(base.add(Offsets.LogicLocalizationGetString),
        {
            onEnter: function (args) {
                this.tid = args[0].readCString();
                if (this.tid.startsWith("TID_BOT_")) {
                    let botIndex = parseInt(this.tid.slice(8), 10) - 1;
                    args[0].writeUtf8String(botNames[botIndex]);
                }
                else if (this.tid == "TID_ABOUT") {
                    args[0].writeUtf8String(credits);
                }
                if (this.tid == "TID_CLUB_FEATURE_LOCKED_TROPHIES") {
                    args[0].writeUtf8String("Clubs not implemented");
                }
                /*
                if (this.tid == "LATENCY TESTS") {
                    args[0].writeUtf8String("Source Code");
                }
                */
            }
        });

    Interceptor.attach(base.add(Offsets.LogicConfDataGetIntValue),
        {
            onEnter: function (args) {
                if (args[1].equals(ptr(5)) || args[1].equals(ptr(37)))
                    this.retval = ptr(1);
            },

            onLeave: function (retval) {
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
            //console.log("Length", PiranhaMessage.getMessageLength(message));

            if (type == 10100 || type == 10101) { // ClientHelloMessage
                Messaging.sendOfflineMessage(20104, LoginOkMessage.encode(player));
                Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
            }
            else if (type == 14109) { // GoHomeFromOfflinePracticeMessage
                Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
            }
            else if (type == 14113) { // GetPlayerProfileMessage
                Messaging.sendOfflineMessage(24113, PlayerProfileMessage.encode(player));
            }

            PiranhaMessage.destroyMessage(message);

            return 0;
        }, "int", ["pointer", "pointer"])
    );

    Interceptor.attach(base.add(Offsets.HomePageButtonClicked),
        {
            onEnter(args) {
                let button = decodeString(args[1].add(Offsets.ClickedButtonName));
                console.log("HomePage::buttonClicked", button);
                return;
            }
        });

    Interceptor.attach(base.add(Offsets.IsAllianceFeatureAvailable),
        {
            onLeave(retval) {
                retval.replace(ptr(0));
            }
        });

    Interceptor.attach(base.add(Offsets.HomePageUpdate),
        {
            onEnter(args) {
                homePageInstance = args[0];
            }
        });


    Interceptor.attach(base.add(Offsets.HomePageGetButtonByName),
        {
            onEnter(args) {
                let name = decodeString(args[1]);
            },
        })

    Interceptor.attach(base.add(Offsets.DropGUIContainerAddGameButton),
        {
            onEnter(args) {
                console.log("DropGUIContainer::addGameButton", decodeString(args[2]))
            },
        })

    Interceptor.attach(base.add(Offsets.GameGUIContainerAddGameButton),
        {
            onEnter(args) {
                console.log("GameGUIContainer::addGameButton", args[1].readCString());
            },
        });

    Interceptor.attach(base.add(Offsets.GUIContainerAddButton),
        {
            onEnter(args) {
                console.log("GUIContainer::addButton", args[1].readCString());
            },
        }
    );

    Interceptor.attach(base.add(Offsets.HomeModeEnter),
        {
            onLeave() {
                createDebugButton();
            }
        });

    Interceptor.attach(base.add(Offsets.NativeFontFormatString),
        {
            onEnter(args) {
                args[7] = ptr(1);
            },
        });

    Interceptor.attach(base.add(Offsets.LogicDailyButtonGetBrawlPassSeasonData), {
        onLeave(retval) {
            if (!retval.isNull()) {
                (Memory as any).writeU8(retval.add(Offsets.BrawlPassPremiumFlag), 1);
            }
        }
    });
}