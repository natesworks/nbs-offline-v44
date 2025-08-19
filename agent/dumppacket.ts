import { dataDirectory, EEXIST, ENOENT, errno, packetDumpsDirectory } from "./definitions.js";
import { createDirectory, openFile, writeFile, writeFileBytes } from "./fs.js";
import { Logger } from "./logger.js";

export function dumpPacket(id : number, payload : number[])
{
    if(createDirectory(packetDumpsDirectory) != 0)
    {
        let error = errno().readS32();
        if (error != EEXIST)
        {
            Logger.error("Failed to create packet dumps directory at", packetDumpsDirectory);
            return;
        }
        Logger.debug("Packet dumps directory already exists");
    }
    let dumpFilePath = `${packetDumpsDirectory}/${id}.bin`;
    let dumpFile = openFile(dumpFilePath, true);
    if (dumpFile < 0)
    {
        Logger.error("Failed to write to", dumpFilePath);
        return;
    }
    writeFileBytes(dumpFile, new Uint8Array(payload));
}