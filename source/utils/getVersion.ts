import { XMLParser } from 'fast-xml-parser';
import * as tomlParser from 'toml';
import * as fs from 'fs';

import { Options, PackageManager } from '@/types/Options.js';
import { getNestedProperty } from './getNestedProperty.js';

function getJsonContent(inputPath: string): any {
    const fileContentTxt = fs.readFileSync(inputPath, 'utf8');
    const fileContent = JSON.parse(fileContentTxt);
    return fileContent;
}

function getXmlContent(inputPath: string): any {
    const fileContentTxt = fs.readFileSync(inputPath, 'utf8');
    const fileContent = new XMLParser().parse(fileContentTxt);
    return fileContent;
}

function getTomlContent(inputPath: string): any {
    const fileContentTxt = fs.readFileSync(inputPath, 'utf8');
    const fileContent = tomlParser.parse(fileContentTxt);
    return fileContent;
}

function getFileContent(inputPath: string, options: Options): any {
    switch (options.packageManager) {
        case PackageManager.NPM:
        case PackageManager.COMPOSER:
            return getJsonContent(inputPath);
        case PackageManager.MAVEN:
            return getXmlContent(inputPath);
        case PackageManager.PIPENV:
        case PackageManager.POETRY:
            return getTomlContent(inputPath);
        default:
            throw new Error(`Unknown package manager ${options.packageManager}`);
    }
}

export function getVersion(inputPath: string, options: Options): string {
    const fileContent = getFileContent(inputPath, options);
    const version: string | undefined = getNestedProperty(fileContent, options.versionProp);

    if (!version) {
        throw new Error(`No version found in ${inputPath} within property ${options.versionProp}`);
    }

    return String(version);
}
