import { Brawler } from "./brawler.js";
import { base, close, malloc, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, open, possibleBotNames, read, stringCtor, write } from "./definitions.js";
import { Logger } from "./logger.js";
import { Offsets } from "./offsets.js";

export function getMessageManagerInstance(): NativePointer {
    return base.add(Offsets.MessageManagerInstance).readPointer();
}

export function getBotNames(): string[] {
    const shuffled = [...possibleBotNames]
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1))
        const temp = shuffled[i]
        shuffled[i] = shuffled[j]
        shuffled[j] = temp
    }

    return shuffled.slice(0, 9)
}

export function decodeString(src: NativePointer): string | null {
    const length = src.add(4).readInt();
    if (length >= 8) {
        return src.add(Process.pointerSize * 2).readPointer().readUtf8String(length);
    }
    return src.add(Process.pointerSize * 2).readUtf8String(length);
}

export function strPtr(message: string) {
    const charPtr = malloc(message.length + 1);
    (Memory as any).writeUtf8String(charPtr, message);
    return charPtr;
}

export function createStringObject(text: string) {
    const strptr = strPtr(text);
    const ptr = malloc(128);
    stringCtor(ptr, strptr);
    return ptr;
}

export function openFile(path: string, rw = false) {
    const p = Memory.allocUtf8String(path);
    const fd = open(p, rw ? O_CREAT | O_RDWR : O_RDONLY, 0o666);
    if (fd < 0) throw new Error("open failed: " + path);
    return fd;
}

export function readFile(fd: number) {
    const buf = Memory.alloc(4096);
    let chunks: ArrayBuffer[] = [];
    while (true) {
        const n = read(fd, buf, 4096);
        if (n <= 0) break;
        const chunk = buf.readByteArray(n);
        if (chunk) chunks.push(chunk);
    }
    let raw = "";
    for (const chunk of chunks) {
        raw += String.fromCharCode(...new Uint8Array(chunk));
    }
    return raw;
}

export function writeFile(fd: number, content: string) {
    const {
        ptr,
        len
    } = utf8ToBytes(content);
    let total = 0;
    while (total < len) {
        const n = write(fd, ptr.add(total), Math.min(4096, len - total));
        if (n < 0) {
            close(fd);
            throw new Error("write failed");
        }
        total += n;
    }
    return total;
}

export function copyFile(src: string, dst: string, overwrite = true) {
    let dstFd;
    if (!overwrite) {
        const p = Memory.allocUtf8String(dst);
        dstFd = open(p, O_RDWR, 0o666);
        if (dstFd >= 0) { // file exists/perm error
            close(dstFd);
            return;
        }
    }
    dstFd = openFile(dst, true);
    const srcFd = openFile(src);
    writeFile(dstFd, readFile(srcFd));
    close(srcFd);
    close(dstFd);
    return;
}

export function getLibraryDir() {
    const fd = openFile("/proc/self/maps");
    const maps = readFile(fd)
    close(fd);
    const lines = maps.split("\n")
    let libName = "libNBS.so" // if u renamed it then skill issue tbh

    for (const line of lines) {
        const parts = line.trim().split(/\s+/)
        if (parts.length >= 6) {
            const path = parts[5]
            if (path.includes(libName)) {
                const lastSlash = path.lastIndexOf("/")
                return lastSlash !== -1 ? path.slice(0, lastSlash) : path
            }
        }
    }

    throw new Error("libNBS.so not found")
}

export function calculateTrophies(brawlerData: Record<number, Brawler>): number {
    let trophies = 0;
    for (const [_, brawler] of Object.entries(brawlerData as Record<string, any>)) {
        trophies += brawler.highestTrophies;
    }
    return trophies;
}

export function calculateHighestTrophies(brawlerData: Record<number, Brawler>): number {
    let trophies = 0;
    for (const [_, brawler] of Object.entries(brawlerData as Record<string, any>)) {
        trophies += brawler.highestTrophies;
    }
    return trophies;
}

export function sleep(ms: number) {
    var start = Date.now();
    while (Date.now() - start < ms) { }
}

// cant use TextEncoder or TextDecoder in frida so skidded this thing
export function utf8ArrayToString(array: Uint8Array): string {
    let out = '', i = 0, len = array.length
    while (i < len) {
        let c = array[i++]
        if (c < 128) {
            out += String.fromCharCode(c)
        } else if (c > 191 && c < 224) {
            let c2 = array[i++]
            out += String.fromCharCode(((c & 31) << 6) | (c2 & 63))
        } else {
            let c2 = array[i++]
            let c3 = array[i++]
            out += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63))
        }
    }
    return out
}

export function stringToUtf8Array(str: string): Uint8Array {
    let utf8 = []
    for (let i = 0; i < str.length; i++) {
        let charcode = str.charCodeAt(i)
        if (charcode < 0x80) {
            utf8.push(charcode)
        } else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                0x80 | (charcode & 0x3f))
        } else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                0x80 | ((charcode >> 6) & 0x3f),
                0x80 | (charcode & 0x3f))
        } else {
            i++
            let surrogatePair = 0x10000 + (((charcode & 0x3ff) << 10)
                | (str.charCodeAt(i) & 0x3ff))
            utf8.push(0xf0 | (surrogatePair >> 18),
                0x80 | ((surrogatePair >> 12) & 0x3f),
                0x80 | ((surrogatePair >> 6) & 0x3f),
                0x80 | (surrogatePair & 0x3f))
        }
    }
    return new Uint8Array(utf8)
}

export function utf8ByteLength(s: string) {
    let bytes = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c < 0x80) bytes += 1;
        else if (c < 0x800) bytes += 2;
        else if (c >= 0xD800 && c <= 0xDBFF) {
            bytes += 4;
            i++;
        } else bytes += 3;
    }
    return bytes;
}

export function utf8ToBytes(s: string) {
    const len = utf8ByteLength(s);
    const buf = malloc(len);
    let off = 0;
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);
        if (c < 0x80) {
            buf.add(off++).writeU8(c);
        } else if (c < 0x800) {
            buf.add(off++).writeU8(0xC0 | (c >> 6));
            buf.add(off++).writeU8(0x80 | (c & 0x3F));
        } else if (c >= 0xD800 && c <= 0xDBFF) {
            const high = c;
            const low = s.charCodeAt(++i);
            const cp = ((high - 0xD800) << 10) + (low - 0xDC00) + 0x10000;
            buf.add(off++).writeU8(0xF0 | (cp >> 18));
            buf.add(off++).writeU8(0x80 | ((cp >> 12) & 0x3F));
            buf.add(off++).writeU8(0x80 | ((cp >> 6) & 0x3F));
            buf.add(off++).writeU8(0x80 | (cp & 0x3F));
        } else {
            buf.add(off++).writeU8(0xE0 | (c >> 12));
            buf.add(off++).writeU8(0x80 | ((c >> 6) & 0x3F));
            buf.add(off++).writeU8(0x80 | (c & 0x3F));
        }
    }
    return {
        ptr: buf,
        len
    };
}

export function displayObjectGetXY(displayobject : NativePointer) : number[]
{
    let x = displayobject.add(Offsets.PosX).readPointer().toInt32();
    let y = displayobject.add(Offsets.PosY).readPointer().toInt32();
    return [x, y];
}