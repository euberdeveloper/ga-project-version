import * as path from 'path';

import { Options, PackageManager } from '../types/Options';

function getPackageManagerConfigFileName(packageManager: PackageManager): string {
    switch (packageManager) {
        case PackageManager.NPM:
            return 'package.json';
        case PackageManager.COMPOSER:
            return 'composer.json';
        case PackageManager.MAVEN:
            return 'pom.xml';
        case PackageManager.PIPENV:
            return 'Pipfile';
        case PackageManager.POETRY:
            return 'pyproject.toml';
    }
}

export function getPath(options: Options): string {
    if (options.path) {
        return path.join(process.cwd(), options.path);
    }

    const filename = getPackageManagerConfigFileName(options.packageManager);
    return path.join(process.cwd(), options.rootDirectory, filename);
}
