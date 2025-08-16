import { android_log_write, pkg } from "./definitions.js";
import { readFile, writeFile } from "./util.js";

const ANDROID_LOG_INFO = 4;
const ANDROID_LOG_DEBUG = 3;
const ANDROID_LOG_WARN = 5;
const ANDROID_LOG_ERROR = 6;

const tag = Memory.allocUtf8String("NBSOFFLINE");

function androidLog(level: number, text: string): void {
    const message = Memory.allocUtf8String(text);
    android_log_write(level, tag, message);
}

function getTimestamp(): string {
    const d = new Date();
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = String(d.getFullYear()).slice(2);
    const hh = String(d.getHours()).padStart(2, '0');
    const mi = String(d.getMinutes()).padStart(2, '0');
    return `[${dd}/${mm}/${yy} ${hh}:${mi}]`;
}

export class Logger {
    private static format(args: any[]): string {
        return args.map(a => typeof a === "string" ? a : JSON.stringify(a)).join(" ");
    }

    static info(...args: any[]): void {
        const logFile = `/data/data/${pkg}/files/log.txt`; // when declaring it in global scope it breaks
        const msg = Logger.format(args);
        const line = `${getTimestamp()} [INFO] ${msg}`;
        console.log(line);
        writeFile(logFile, readFile(logFile) + line + "\n");
        androidLog(ANDROID_LOG_INFO, msg);
    }

    static debug(...args: any[]): void {
        const logFile = `/data/data/${pkg}/files/log.txt`;
        const msg = Logger.format(args);
        const line = `${getTimestamp()} [DEBUG] ${msg}`;
        console.log(line);
        writeFile(logFile, readFile(logFile) + line + "\n");
        androidLog(ANDROID_LOG_DEBUG, msg);
    }

    static warn(...args: any[]): void {
        const logFile = `/data/data/${pkg}/files/log.txt`;
        const msg = Logger.format(args);
        const line = `${getTimestamp()} [WARN] ${msg}`;
        console.log(line);
        writeFile(logFile, readFile(logFile) + line + "\n");
        androidLog(ANDROID_LOG_WARN, msg);
    }

    static error(...args: any[]): void {
        const logFile = `/data/data/${pkg}/files/log.txt`;
        const msg = Logger.format(args);
        const line = `${getTimestamp()} [ERROR] ${msg}`;
        console.log(line);
        writeFile(logFile, readFile(logFile) + line + "\n");
        androidLog(ANDROID_LOG_ERROR, msg);
    }
}
