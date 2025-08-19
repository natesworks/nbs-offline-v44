import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { base, brawlPassButtonIsDisabled, config, credits, displayObjectSetSetXY, friendlyGameLevelRequirement, getMovieClipByName, hiddenButtons, hiddenText, logicCharacterServerChargeUlti, malloc, player, radioButtonCreate, shopIsDisabled, stringCtor } from "./definitions.js";
import { Messaging } from "./messaging.js";
import { LoginOkMessage } from "./packets/server/LoginOkMessage.js";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage.js";
import { getBotNames, decodeString, sleep, createStringObject, strPtr, displayObjectGetXY } from "./util.js";
import { PlayerProfileMessage } from "./packets/server/PlayerProfileMessage.js";
import { createDebugButton } from "./debugmenu.js";
import { TeamMessage } from "./packets/server/TeamMessage.js";
import { Logger } from "./logger.js";

let botNames: string[] = [];
let enableFriendRequestsPos : number[];

export function installHooks() {
    Interceptor.attach(base.add(Offsets.ServerConnectionUpdate), {
        onEnter: function (args) {
            args[0].add(Process.pointerSize).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
            args[0].add(Process.pointerSize).readPointer().add(Offsets.State).writeInt(5);
        }
    });

    Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage), {
        onLeave: function (retval) {
            retval.replace(ptr(1));
        }
    });

    Interceptor.attach(base.add(Offsets.HomePageStartGame), {
        onEnter: function (args) {
            args[3] = ptr(3);
            botNames = getBotNames();
        }
    });

    /* to hide the debug ui; on newer versions instead just replace retval of LogicVersion::isDebugUIAvailable */
    Interceptor.attach(base.add(Offsets.CombatHUDButtonClicked), {
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

    Interceptor.attach(base.add(Offsets.LogicLocalizationGetString), {
        onEnter: function (args) {
            this.tid = args[0].readCString();
            if (this.tid.startsWith("TID_BOT_")) {
                let botIndex = parseInt(this.tid.slice(8), 10) - 1;
                args[0].writeUtf8String(botNames[botIndex]);
            }
            else if (this.tid == "TID_ABOUT") {
                args[0].writeUtf8String(credits);
            }
            else if (this.tid == "TID_CLUB_FEATURE_LOCKED_TROPHIES") {
                args[0].writeUtf8String("Clubs not implemented");
            }
            else if (this.tid == "TID_EDIT_CONTROLS") {
                args[0].writeUtf8String("Settings");
            }
        }
    });

    Interceptor.attach(base.add(Offsets.LogicConfDataGetIntValue), {
        onEnter: function (args) {
            let val = args[1];
            if (val.equals(ptr(shopIsDisabled)))
                this.retval = ptr(config.enableShop ? 0 : 1);
            else if (val.equals(ptr(brawlPassButtonIsDisabled)))
                this.retval = ptr(config.enableBrawlPass ? 0 : 1);
            else if (val.equals(ptr(friendlyGameLevelRequirement)))
                this.retval = ptr(0);
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

            if (type == 10108)
                return 0;

            Logger.debug("Type:", type);
            //Logger.debug("Length", PiranhaMessage.getMessageLength(message));

            if (type == 10100 || type == 10101) { // ClientHelloMessage; LoginMessage
                Messaging.sendOfflineMessage(20104, LoginOkMessage.encode(player));
                Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
            }
            else if (type == 14109) { // GoHomeFromOfflinePracticeMessage
                Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
            }
            else if (type == 14113) { // GetPlayerProfileMessage
                Messaging.sendOfflineMessage(24113, PlayerProfileMessage.encode(player));
            }
            else if (type == 14350) { // TeamCreateMessage
                //Messaging.sendOfflineMessage(24124, TeamMessage.encode(player));
            }

            PiranhaMessage.destroyMessage(message);

            return 0;
        }, "int", ["pointer", "pointer"])
    );

    Interceptor.attach(base.add(Offsets.HomePageButtonClicked), {
        onEnter(args) {
            let button = decodeString(args[1].add(Offsets.ClickedButtonName));
            Logger.debug("HomePage::buttonClicked", button);
            return;
        }
    });

    Interceptor.attach(base.add(Offsets.IsAllianceFeatureAvailable), {
        onLeave(retval) {
            retval.replace(ptr(Number(config.enableClubs)));
        }
    });

    Interceptor.attach(base.add(Offsets.HomePageGetButtonByName), {
        onEnter(args) {
            let name = decodeString(args[1]);
            //Logger.debug("HomePage::GetButtonByName", name); // uncomment for 4 seconds per frame
        },
    })

    Interceptor.attach(base.add(Offsets.DropGUIContainerAddGameButton), {
        onEnter(args) {
            let button = decodeString(args[2]);
            Logger.debug("DropGUIContainer::addGameButton", button)
            if (button == "chat_button") {
                Logger.debug("Sleeping for a lazy race condition fix");
                sleep(1000);
            }
        }
    })

    Interceptor.attach(base.add(Offsets.GameGUIContainerAddGameButton), {
        onEnter(args) {
            let button = args[1].readCString();
            Logger.debug("GameGUIContainer::addGameButton", button);
            if (button == "button_credits") this.credits = true;
            if (button != null && hiddenButtons.includes(button)) this.hide = true;
        },
        onLeave(retval) {
            if (this.hide) displayObjectSetSetXY(retval, -1000, -1000);
            if (this.credits) displayObjectSetSetXY(retval, enableFriendRequestsPos[0], enableFriendRequestsPos[1])
        },
    });

    Interceptor.attach(base.add(Offsets.GUIContainerAddButton), {
        onEnter(args) {
            Logger.debug("GUIContainer::addButton", args[1].readCString());
        }
    }
    );

    Interceptor.attach(base.add(Offsets.HomeModeEnter), {
        onLeave() {
            //createDebugButton();
        }
    });

    Interceptor.attach(base.add(Offsets.NativeFontFormatString), {
        onEnter(args) {
            args[7] = ptr(1);
        },
    });

    Interceptor.attach(base.add(Offsets.LogicDailyButtonGetBrawlPassSeasonData), {
        onLeave(retval) {
            if (!retval.isNull()) {
                (Memory as any).writeU8(retval.add(Offsets.BrawlPassPremiumFlag), Number(config.brawlPassPremium));
            }
        }
    });

    Interceptor.attach(base.add(Offsets.LogicSkillDataGetMaxCharge), {
        onLeave(retval) {
            if (config.infiniteAmmo)
                retval.replace(ptr(0));
        },
    });

    if (config.disableBots) {
        Interceptor.replace(base.add(Offsets.LogicCharacterServerTickAI), new NativeCallback(function (a1) {
            return a1;
        }, 'int', ['int']));
    }

    Interceptor.attach(base.add(Offsets.LogicSkillDataCanMoveAtSameTime), {
        onLeave(retval) {
            // retval.replace(ptr(1));
        },
    });

    Interceptor.attach(base.add(Offsets.LogicCharacterDataGetUltiChargeMul), {
        onLeave(retval) {
            if (config.infiniteSuper)
                retval.replace(ptr(6969));
        },
    });

    Interceptor.attach(base.add(Offsets.LogicCharacterDataGetUltiChargeUltiMul), {
        onLeave(retval) {
            if (config.infiniteSuper)
                retval.replace(ptr(6969));
        },
    });

    /*
    Interceptor.attach(base.add(Offsets.RadioButtonCreateButton), {
        onEnter(args) {
            if (decodeString(args[1]) == "locked_movement_controls_button") {
                Logger.debug("Adding radio buttons");
                let disableBotsButtonStr = createStringObject("disable_bots_button");
                Logger.debug("Creating", decodeString(disableBotsButtonStr));
                // let disableBotsButton = radioButtonCreate(args[0], disableBotsButtonStr, args[2]);
            }
        },
    });
    */

    Interceptor.attach(base.add(Offsets.GetMovieClipByName), {
        onEnter(args) {
            let movieClip = args[1].readCString();
            //Logger.debug(movieClip) // do not uncomment if you dont want to get insane spam and a logfile in gigabytes
            if (movieClip == "button_allow_friend_requests")
                this.allowFriendRequests = true;
        },
        onLeave(retval) {
            if (this.allowFriendRequests) {
                enableFriendRequestsPos = displayObjectGetXY(retval);
                displayObjectSetSetXY(retval, -1000, -1000);
            }
        },
    });

    Interceptor.attach(base.add(Offsets.TextFieldSetText), {
        onEnter(args) {
            let text = decodeString(args[1]);
            let info = "<c62a0ea>N<c62a0ea>B<c62a0ea>S<c62a0ea> <c62a0ea>O<c62a0ea>f<c61a0ea>f<c62a0ea>l<c62a0ea>i<c62a0ea>n<c62a0ea>e<c62a0ea> <c62a0ea>V<c62a0ea>2<c62a0ea>.<c61a0ea>3<c62a0ea>.<c62a0ea>1</c>\nMade by Natesworks\ndsc.gg/natesworks\nnbs.brawlmods.com";
            let lobbyInfo = `${info}\n${config.lobbyinfo}`
            if (text?.includes("0-1 not in Club"))
                args[1] = createStringObject(lobbyInfo);
            if (hiddenText.some((x) => x === text)) // .some is cool
                args[1] = createStringObject("");
            //Logger.debug("TextField::SetText", text);
        },
    });
}