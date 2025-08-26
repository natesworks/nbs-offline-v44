import { addFile, base, branches, commodityCountChangedHelper, config, customButtonSetMovieClip, displayObjectSetScale, displayObjectSetSetXY, gameButtonConstructor, gameButtonSetText, guiGetInstance, homeModeGetInstance, logicClientAvatarUseDiamonds, logicDataTablesGetGoldData, logicHomeModeGetPlayerAvatar, malloc, movieClipSetText, reloadGameInternal, resourceManagerGetMovieClip, showFloaterTextAtDefaultPos, stageAddChild, stageRemoveChild, updaterConfig } from "./definitions.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";
import { getScaleX, getScaleY, getScreenHeight, getScreenWidth } from "./scaling.js";
import { switchBranch } from "./updaterutil.js";
import { createStringObject, strPtr } from "./util.js";

let debugMenu: NativePointer;
let debugMenuTitle: NativePointer;
let debugMenuDescription: NativePointer;
let closeButton: NativePointer;

export let debugMenuOpened = false;

let generalCategory: NativePointer | null = null;
let accountCategory: NativePointer | null = null;
let battleCategory: NativePointer | null = null;

let generalCategoryOpened = false;
let accountCategoryOpened = false;
let battleCategoryOpened = false;

export let toggleButton: NativePointer;

let reloadGameButton: NativePointer | null = null;

let infiniteSuperButton: NativePointer | null = null;
let toggleBotsButton: NativePointer | null = null;
let toggleArtTestButton: NativePointer | null = null;

let addGemsButton: NativePointer | null = null;
let addCoinsButton: NativePointer | null = null;

let branchRow: number;
let branchButtons: NativePointer[] = [];

let debugButtonX: number;
let debugButtonY: number;
let debugMenuX: number;
let buttonX: number;
let firstButton: number;
let buttonOffset: number;
let branchY: number;
let firstBranchX: number;
let branchXOffset: number;
let branchYOffset : number;
let menuTitleX: number;
let menuTitleY: number;
let menuDescriptionX: number;
let menuDescriptionY: number;
let closeButtonX: number;
let closeButtonY: number;

const generalCategoryButtonCount = 1;
const accountCategoryButtonCount = 2;
const battleCategoryButtonCount = 3;

function getGeneralCategoryPosition() {
    return firstButton;
}

function getAccountCategoryPosition() {
    let pos = firstButton + buttonOffset;
    if (generalCategoryOpened)
        pos += buttonOffset * generalCategoryButtonCount;
    return pos;
}

function getBattleCategoryPositon() {
    let pos = firstButton + 2 * buttonOffset;
    if (generalCategoryOpened)
        pos += buttonOffset * generalCategoryButtonCount;
    if (accountCategoryOpened)
        pos += buttonOffset * accountCategoryButtonCount;
    return pos;
}

export function addDebugFile() {
    const adder = Interceptor.attach(base.add(Offsets.ResourceListenerAddFile),
        {
            onEnter(args) {
                adder.detach();
                addFile(args[0], createStringObject("sc/debug.sc"), -1, -1, -1, -1, 0);
                Logger.debug("sc/debug.sc loaded");
            }
        });
}

export function createDebugItem(item: string, text: string, x: number, y: number): NativePointer {
    let mem = malloc(512);
    gameButtonConstructor(mem);
    let movieClip = resourceManagerGetMovieClip(strPtr("sc/debug.sc"), strPtr(item), 1);
    customButtonSetMovieClip(mem, movieClip);
    displayObjectSetSetXY(mem, x, y);
    gameButtonSetText(mem, createStringObject(text), 1);
    return mem;
}

export function createDebugButton() {
    Logger.debug("Creating debug button");
    Logger.debug("Screen width: " + getScreenWidth() + ",screen height:" + getScreenHeight());
    toggleButton = createDebugItem("debug_button", "D", debugButtonX, debugButtonY);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleButton);
}

export function spawnBranchButton(branch: string, prettyName: string, index: number) {
    let text = prettyName;
    if (updaterConfig?.branch == branch)
        text = `<c00ff00>${prettyName}</c>`;
    if (index > 0 && index % 4 === 0) branchRow++;
    let button = createDebugItem("debug_menu_item_small", text, firstBranchX + (index % 4) * branchXOffset, branchY + branchRow * branchYOffset);
    branchButtons.push(button);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), button);
}

export function createDebugMenu() {
    Logger.debug("Creating debug menu");
    branchRow = 0;
    debugMenu = createDebugItem("debug_menu", "Debug Menu", debugMenuX, 0);

    debugMenuTitle = createDebugItem("debug_menu_text", "<c62a0ea>NBS Offline</c>", menuTitleX, menuTitleY);
    displayObjectSetScale(debugMenuTitle, 1.5);
    debugMenuDescription = createDebugItem("debug_menu_text", "<c62a0ea>dsc.gg/nbsoffline</c>", menuDescriptionX, menuDescriptionY);
    closeButton = createDebugItem("nothing", "", closeButtonX, closeButtonY);
    displayObjectSetScale(closeButton, 0.80);

    generalCategory = createDebugItem("debug_menu_category", (generalCategoryOpened ? "- " : "+ ") + "General", buttonX, getGeneralCategoryPosition());
    accountCategory = createDebugItem("debug_menu_category", (accountCategoryOpened ? "- " : "+ ") + "Account", buttonX, getAccountCategoryPosition());
    battleCategory = createDebugItem("debug_menu_category", (battleCategoryOpened ? "- " : "+ ") + "Battle", buttonX, getBattleCategoryPositon());

    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenuTitle);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), debugMenuDescription);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), closeButton);

    branchButtons = [];
    if (branches != undefined && branches.size > 0) {
        Array.from(branches.entries()).forEach(([branch, text], index) =>
            spawnBranchButton(text, branch, index)
        );
    }
}

export function updateDebugMenu() {
    Logger.debug("Updating debug menu");

    if (generalCategory) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    }
    if (accountCategory) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);
    }
    if (battleCategory) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    }

    if (reloadGameButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
        reloadGameButton = null;
    }

    if (infiniteSuperButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        infiniteSuperButton = null;
    }
    if (toggleBotsButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        toggleBotsButton = null;
    }
    if (toggleArtTestButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
        toggleArtTestButton = null;
    }
    if (addGemsButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), addGemsButton);
        addGemsButton = null;
    }
    if (addCoinsButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), addCoinsButton);
        addCoinsButton = null;
    }

    generalCategory = createDebugItem("debug_menu_category", (generalCategoryOpened ? "- " : "+ ") + "General", buttonX, getGeneralCategoryPosition());
    accountCategory = createDebugItem("debug_menu_category", (accountCategoryOpened ? "- " : "+ ") + "Account", buttonX, getAccountCategoryPosition());
    battleCategory = createDebugItem("debug_menu_category", (battleCategoryOpened ? "- " : "+ ") + "Battle", buttonX, getBattleCategoryPositon());

    if (generalCategoryOpened) {
        reloadGameButton = createDebugItem("debug_menu_item", "Reload Game", buttonX, getGeneralCategoryPosition() + buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
    }

    if (accountCategoryOpened) {
        addGemsButton = createDebugItem("debug_menu_item", "Add Gems", buttonX, getAccountCategoryPosition() + buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), addGemsButton);
        addCoinsButton = createDebugItem("debug_menu_item", "Add Coins", buttonX, getAccountCategoryPosition() + 2 * buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), addCoinsButton);
    }

    if (battleCategoryOpened) {
        infiniteSuperButton = createDebugItem("debug_menu_item", "Infinite Super", buttonX, getBattleCategoryPositon() + buttonOffset);
        toggleBotsButton = createDebugItem("debug_menu_item", (config.disableBots ? "Enable" : "Disable") + " Bots", buttonX, getBattleCategoryPositon() + 2 * buttonOffset);
        toggleArtTestButton = createDebugItem("debug_menu_item", (config.artTest ? "Disable" : "Enable") + " Art Test", buttonX, getBattleCategoryPositon() + 3 * buttonOffset);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        stageAddChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
    }

    stageAddChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    stageAddChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);
}

export function hideDebugMenu() {
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenu);

    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenuTitle);
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), debugMenuDescription);
    stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), closeButton);

    if (generalCategory) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), generalCategory);
    if (battleCategory) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), battleCategory);
    if (accountCategory) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), accountCategory);

    if (generalCategoryOpened && reloadGameButton) {
        stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), reloadGameButton);
    }

    if (accountCategoryOpened) {
        if (addGemsButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), addGemsButton);
        if (addCoinsButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), addCoinsButton);
    }

    if (battleCategoryOpened) {
        if (infiniteSuperButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), infiniteSuperButton);
        if (toggleBotsButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleBotsButton);
        if (toggleArtTestButton) stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), toggleArtTestButton);
    }

    branchButtons.forEach((button) => stageRemoveChild(base.add(Offsets.StageInstance).readPointer(), button));
}

export function toggleDebugMenu() {
    if (!debugMenuOpened) createDebugMenu()
    else hideDebugMenu()
    debugMenuOpened = !debugMenuOpened;
}

export function toggleInfiniteSuper() {
    config.infiniteSuper = !config.infiniteSuper;
    let text = `Infinite super is now ${config.infiniteSuper ? "enabled" : "disabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
}

export function toggleBots() {
    config.disableBots = !config.disableBots;
    let text = `Bots are now ${config.disableBots ? "disabled" : "enabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
    if (toggleBotsButton) gameButtonSetText(toggleBotsButton, createStringObject((config.disableBots ? "Enable" : "Disable") + " Bots"), 1);
}

export function toggleArtTest() {
    config.artTest = !config.artTest;
    let text = `Art test is now ${config.artTest ? "enabled" : "disabled"}!`;
    Logger.debug(text);
    showFloaterTextAtDefaultPos(guiGetInstance(), createStringObject(text), 0.0, -1);
    if (toggleArtTestButton) gameButtonSetText(toggleArtTestButton, createStringObject((config.artTest ? "Disable" : "Enable") + " Art Test"), 1);
    (Memory as any).writeU8(base.add(Offsets.ArtTest), Number(config.artTest));
}

export function addGems(amount: number) {
    Logger.debug(`Adding ${amount} gems`);
    logicClientAvatarUseDiamonds(logicHomeModeGetPlayerAvatar(homeModeGetInstance()), -amount);
}

export function addCoins(amount: number) {
    Logger.debug(`Adding ${amount} coins`);
    //commodityCountChangedHelper(logicHomeModeGetPlayerAvatar(homeModeGetInstance()), logicDataTablesGetGoldData(), amount, 1, 0, 3);
}

export function loadDebug() {
    debugButtonX = 1.4 * getScaleX();
    debugButtonY = 575 * getScaleY();
    debugMenuX = 1280 * getScaleX();
    buttonX = 1131 * getScaleX();
    firstButton = 100 * getScaleX();
    buttonOffset = 55 * getScaleY();
    branchY = 95 * getScaleY();
    firstBranchX = 1022.5 * getScaleX();
    branchXOffset = 72.5 * getScaleX();
    branchYOffset = 40 * getScaleY();
    menuTitleX = 1075 * getScaleX();
    menuTitleY = 0 * getScaleY();
    menuDescriptionX = 1075 * getScaleX();
    menuDescriptionY = 20 * getScaleY();
    closeButtonX = 1256 * getScaleX();
    closeButtonY = 24 * getScaleY();
    if (branches != undefined && branches.size > 0)
        firstButton += (((branches.size + 3) / 4) * branchYOffset + 5) * getScaleY();

    Interceptor.attach(base.add(Offsets.CustomButtonButtonPressed),
        {
            onEnter(args) {
                if (args[0].equals(toggleButton) || args[0].equals(closeButton)) toggleDebugMenu();
                else if (generalCategory && args[0].equals(generalCategory)) generalCategoryOpened = !generalCategoryOpened;
                else if (accountCategory && args[0].equals(accountCategory)) accountCategoryOpened = !accountCategoryOpened;
                else if (battleCategory && args[0].equals(battleCategory)) battleCategoryOpened = !battleCategoryOpened;
                else if (infiniteSuperButton && args[0].equals(infiniteSuperButton)) toggleInfiniteSuper();
                else if (toggleBotsButton && args[0].equals(toggleBotsButton)) toggleBots();
                else if (toggleArtTestButton && args[0].equals(toggleArtTestButton)) toggleArtTest();
                else if (reloadGameButton && args[0].equals(reloadGameButton)) reloadGameInternal(base.add(Offsets.GameMainInstance));
                else if (addGemsButton && args[0].equals(addGemsButton)) addGems(100);
                else if (addCoinsButton && args[0].equals(addCoinsButton)) addCoins(100);
                else {
                    if (branches == undefined || updaterConfig == undefined) return;
                    const idx = branchButtons.findIndex(b => args[0].equals(b));
                    if (idx !== -1) {
                        const branch = Array.from(branches.values())[idx];
                        switchBranch(branch);
                    }
                    return;
                }

                if (debugMenuOpened) updateDebugMenu();
            },
        });
}