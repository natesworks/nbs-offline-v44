import { close, malloc, mkdir, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, open, read, write } from "./definitions.js";
import { strPtr, utf8ToBytes } from "./util.js";

export function openFile(path: string, rw = false, trunc = false) {
    const p = Memory.allocUtf8String(path);
    const flags = rw ? (O_CREAT | O_RDWR | (trunc ? O_TRUNC : 0)) : O_RDONLY;
    const fd = open(p, flags, 0o666);
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

export function writeFileBytes(fd: number, data: Uint8Array) {
    const ptr = Memory.alloc(data.length);
    (Memory as any).writeByteArray(ptr, data);
    let total = 0;
    while (total < data.length) {
        const n = write(fd, ptr.add(total), Math.min(4096, data.length - total));
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

export function createDirectory(path: string) {
    let pathPtr = strPtr(path);
    return mkdir(pathPtr, 0o755);
}