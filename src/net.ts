// credits: ai

export const socketFn = new NativeFunction(Module.getExportByName(null, 'socket'), 'int', ['int', 'int', 'int']);
export const connectFn = new NativeFunction(Module.getExportByName(null, 'connect'), 'int', ['int', 'pointer', 'int']);
export const sendFn = new NativeFunction(Module.getExportByName(null, 'send'), 'int', ['int', 'pointer', 'int', 'int']);
export const recvFn = new NativeFunction(Module.getExportByName(null, 'recv'), 'int', ['int', 'pointer', 'int', 'int']);
export const closeFn = new NativeFunction(Module.getExportByName(null, 'close'), 'int', ['int']);
export const fcntlFn = new NativeFunction(Module.getExportByName(null, 'fcntl'), 'int', ['int', 'int', 'int']);
export const pollFn = new NativeFunction(Module.getExportByName(null, 'poll'), 'int', ['pointer', 'int', 'int']);
export const getsockoptFn = new NativeFunction(Module.getExportByName(null, 'getsockopt'), 'int', ['int', 'int', 'int', 'pointer', 'pointer']);

export const AF_INET = 2;
export const SOCK_STREAM = 1;
export const F_GETFL = 3;
export const F_SETFL = 4;
export const O_NONBLOCK = 0x0800;
export const POLLIN = 0x0001;
export const POLLOUT = 0x0004;

export const SOL_SOCKET = 1;
export const SO_ERROR = 4;

export function checkConnected(fd: number): boolean {
    const errPtr = Memory.alloc(4);
    errPtr.writeS32(0);
    const lenPtr = Memory.alloc(4);
    lenPtr.writeS32(4);
    const r = getsockoptFn(fd, SOL_SOCKET, SO_ERROR, errPtr, lenPtr);
    if (r !== 0) return false;
    return errPtr.readS32() === 0;
}

export function makeSockaddrIn(ip: string, port: number): NativePointer {
    const sockaddr = Memory.alloc(16);
    sockaddr.writeU16(AF_INET);

    const portBE = ((port & 0xff) << 8) | ((port >> 8) & 0xff);
    sockaddr.add(2).writeU16(portBE >>> 0);

    const parts = ip.split('.').map(p => parseInt(p, 10));
    const ipBytes = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

    const ipBE = ((ipBytes & 0xff) << 24) |
        ((ipBytes & 0xff00) << 8) |
        ((ipBytes & 0xff0000) >>> 8) |
        ((ipBytes >>> 24) & 0xff);
    sockaddr.add(4).writeU32(ipBE >>> 0);

    return sockaddr;
}

export function connectWithTimeout(ip: string, port: number, ms: number): number {
    const fd = socketFn(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const flags = fcntlFn(fd, F_GETFL, 0);
    fcntlFn(fd, F_SETFL, flags | O_NONBLOCK);
    const addr = makeSockaddrIn(ip, port);
    const rc = connectFn(fd, addr, 16);
    if (rc === 0) return fd;
    const pfd = Memory.alloc(8);
    pfd.writeS32(fd);
    pfd.add(4).writeS16(POLLOUT);
    pfd.add(6).writeS16(0);
    const pr = pollFn(pfd, 1, ms);
    if (pr > 0 && checkConnected(fd)) return fd;
    closeFn(fd);
    return -1;
}

export function readAll(fd: number, ms: number): string {
    const buf = Memory.alloc(8192);
    const pfd = Memory.alloc(8);
    pfd.writeS32(fd);
    pfd.add(4).writeS16(POLLIN);
    pfd.add(6).writeS16(0);
    const deadline = Date.now() + ms;
    let out = '';
    while (Date.now() < deadline) {
        const pr = pollFn(pfd, 1, Math.max(0, deadline - Date.now()));
        if (pr <= 0) break;
        const n = recvFn(fd, buf, 8192, 0);
        if (n <= 0) break;
        const s = buf.readUtf8String(n);
        if (s) out += s;
    }
    return out;
}

export function httpBody(resp: string): string {
    const idx = resp.indexOf("\r\n\r\n");
    if (idx < 0) return "";
    const headers = resp.slice(0, idx);
    let body = resp.slice(idx + 4);
    const lower = headers.toLowerCase();
    if (lower.indexOf("transfer-encoding: chunked") !== -1) {
        let i = 0, out = "";
        while (true) {
            const crlf = body.indexOf("\r\n", i);
            if (crlf < 0) break;
            const sizeHex = body.slice(i, crlf).trim();
            const size = parseInt(sizeHex, 16);
            if (!(size >= 0)) break;
            i = crlf + 2;
            if (size === 0) break;
            out += body.substr(i, size);
            i += size + 2;
        }
        return out;
    }
    return body;
}