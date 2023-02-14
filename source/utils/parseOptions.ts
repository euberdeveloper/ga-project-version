import * as core from '@actions/core';

import { Options, PackageManager } from '../types/Options';

function getDefaultVersionProp(packageManager: PackageManager): any {
    switch (packageManager) {
        case PackageManager.NPM:
        case PackageManager.COMPOSER:
            return 'version';
        case PackageManager.MAVEN:
            return 'project.version';
        case PackageManager.PIPENV:
            return 'version';
        case PackageManager.POETRY:
            return 'tool.poetry.version';
        default:
            throw new Error(`Unknown package manager ${packageManager}`);
    }
}

export function parseOptions(): Options {
    const packageManager = core.getInput('package-manager') as PackageManager;
    const rootDirectory = core.getInput('root-directory');
    const path = core.getInput('path');
    const versionProp = core.getInput('version-prop') || getDefaultVersionProp(packageManager);
    const packageManagerValues = Object.values(PackageManager);

    if (!packageManagerValues.includes(packageManager)) {
        throw new Error(
            `Invalid package manager ${packageManager}, possible values: ${JSON.stringify(
                packageManagerValues,
                null,
                2
            )}`
        );
    }

    return {
        packageManager,
        rootDirectory,
        path,
        versionProp
    };
}
