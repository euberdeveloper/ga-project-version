import { XMLParser } from "fast-xml-parser";
import * as fs from 'fs';

import { Options } from "../types/Options";


declare function __non_webpack_require__(path: string): any;

function getVersionJson(path: string, options: Options): string {
    const fileContent = process.env.IS_WEBPACK ? __non_webpack_require__(path) : require(path);
    const version: string = fileContent[options.versionProp];

    if (!version) {
        throw new Error(`No version found in ${path} within property ${options.versionProp}`);
    }

    return version;
}

function getVersionPomXml(path: string, options: Options): string {
    const fileContentTxt = fs.readFileSync(path, 'utf8');
    const fileContent = new XMLParser().parse(fileContentTxt);
    const version: string = fileContent['project'][options.versionProp];

    if (!version) {
        throw new Error(`No version found in ${path} within property ${options.versionProp}`);
    }

    return version;
}

export function getVersion(path: string, options: Options): string {
    switch(options.packageManager) {
        case 'npm':
        case 'composer':
            return getVersionJson(path, options);
        case 'maven':
            return getVersionPomXml(path, options);
        default:
            throw new Error(`Unknown package manager ${options.packageManager}`);
    }
}