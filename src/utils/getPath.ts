import * as path from 'path';

import { Options, PackageManager } from "../types/Options";

function getPackageManagerJsonName(packageManager: PackageManager): string {
    switch (packageManager) {
        case PackageManager.NPM:
            return "package.json";
        case PackageManager.COMPOSER:
            return "composer.json";
    }
}

export function getPath(options: Options): string {
    if (options.path) {
        return path.join(process.cwd(), options.path);
    }

    const filename = getPackageManagerJsonName(options.packageManager);
    return path.join(options.rootDirectory, filename);
}