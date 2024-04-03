import fs from "fs";
import {promisify} from "util";
import {exec} from "child_process";
import {ethers} from "hardhat";

export const memberDir = `./data/members/`
export const mpksPath = `./data/mpks.json`
export const dkgDir = `./data/dkg/`
export const instancesPath = `./data/dkg/all_instances.json`
export const randDir = `./data/random/`

export const execPromise = promisify(exec);
export function readJsonFromFile(filePath: string): any {
    try {
        // Read file content
        let rawdata = fs.readFileSync(filePath, 'utf-8');

        // Parse JSON
        let jsonData = JSON.parse(rawdata);

        return jsonData;
    } catch (error) {
        console.error(error);
        return null;
    }
}

export function writeJsonToFile(obj: string, filePath: string): void {
    // Write the JSON string to a file
    fs.writeFile(filePath, obj, 'utf8', function(err) {
        if (err) {
            console.log("An error occurred while writing JSON Object to File.");
            return console.log(err);
        }

        console.log(`JSON file has been saved at ${filePath}`);
    });
}

export async function waitForWriteJsonToFile(obj: string, filePath: string) {
    console.log('Before writeJsonToFile');
    return new Promise<void>((resolve, reject) => {
        writeJsonToFile(obj, filePath); // Call the function without a callback
        console.log('After writeJsonToFile');
        resolve();
    });
}

export function readBytesFromFile(filePath: string): Uint8Array | null {
    try {
        // Read the file synchronously
        const fileData: Buffer = fs.readFileSync(filePath);

        // Access the bytes of the file
        const bytes: Uint8Array = new Uint8Array(fileData);

        return bytes;
    } catch (err) {
        console.error('Error reading file:', err);
        return null;
    }
}

export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
