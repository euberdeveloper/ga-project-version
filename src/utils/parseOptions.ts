import * as core from '@actions/core';

import { Options, PackageManager } from "../types/Options";

export function parseOptions(): Options {
    const packageManager = core.getInput('package-manager') as PackageManager;
    const rootDirectory = core.getInput('root-directory');
    const path = core.getInput('path');
    const versionProp = core.getInput('version-prop');
    const packageManagerValues = Object.values(PackageManager);

    if (!packageManagerValues.includes(packageManager)) {
        throw new Error(`Invalid package manager ${packageManager}, possible values: ${JSON.stringify(packageManagerValues, null, 2)}`);
    }

    return {
        packageManager,
        rootDirectory,
        path,
        versionProp
    };
}