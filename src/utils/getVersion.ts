import { XMLParser } from "fast-xml-parser";
import * as fs from 'fs';

import { Options } from "../types/Options";
import { getNestedProperty } from "./getNestedProperty";


declare function __non_webpack_require__(path: string): any;

function getJsonContent(inputPath: string): any {
    const fileContent = process.env.IS_WEBPACK ? __non_webpack_require__(inputPath) : require(inputPath);
    return fileContent;
}

function getXmlContent(inputPath: string): any {
    const fileContentTxt = fs.readFileSync(inputPath, 'utf8');
    const fileContent = new XMLParser().parse(fileContentTxt);
    return fileContent;
}

function getFileContent(inputPath: string, options: Options): any {
    switch (options.packageManager) {
        case 'npm':
        case 'composer':
            return getJsonContent(inputPath);
        case 'maven':
            return getXmlContent(inputPath);
        default:
            throw new Error(`Unknown package manager ${options.packageManager}`);
    }
}

export function getVersion(inputPath: string, options: Options): string {
    const fileContent = getFileContent(inputPath, options);
    const version: string = getNestedProperty(fileContent, options.versionProp);

    if (!version) {
        throw new Error(`No version found in ${inputPath} within property ${options.versionProp}`);
    }

    return version;
}
