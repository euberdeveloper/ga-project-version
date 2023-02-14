import { getPath } from '@src/utils/getPath.js'
import { Options, PackageManager } from '@src/types/Options.js';

import path from 'node:path';

describe('Test utility getPath', function () {
    it('Should work with npm`', function () {
        const options: Options = {
            rootDirectory: './myRootDirectory',
            packageManager: PackageManager.NPM,
            versionProp: 'version'
        };
        const result = getPath(options);
        const expected = path.join(process.cwd(), './myRootDirectory/package.json');
        expect(result).toEqual(expected);
    });

    it('Should work with composer`', function () {
        const options: Options = {
            rootDirectory: './myRootDirectory',
            packageManager: PackageManager.COMPOSER,
            versionProp: 'version'
        };
        const result = getPath(options);
        const expected = path.join(process.cwd(), './myRootDirectory/composer.json');
        expect(result).toEqual(expected);
    });

    it('Should work with maven`', function () {
        const options: Options = {
            rootDirectory: './myRootDirectory',
            packageManager: PackageManager.MAVEN,
            versionProp: 'version'
        };
        const result = getPath(options);
        const expected = path.join(process.cwd(), './myRootDirectory/pom.xml');
        expect(result).toEqual(expected);
    });

    it('Should work with poetry`', function () {
        const options: Options = {
            rootDirectory: './myRootDirectory',
            packageManager: PackageManager.POETRY,
            versionProp: 'version'
        };
        const result = getPath(options);
        const expected = path.join(process.cwd(), './myRootDirectory/pyproject.toml');
        expect(result).toEqual(expected);
    });

    it('Should work with Pipenv`', function () {
        const options: Options = {
            rootDirectory: './myRootDirectory',
            packageManager: PackageManager.PIPENV,
            versionProp: 'version'
        };
        const result = getPath(options);
        const expected = path.join(process.cwd(), './myRootDirectory/Pipfile');
        expect(result).toEqual(expected);
    });

    it('Should work with a custom path`', function () {
        const options: Options = {
            rootDirectory: './myRootDirectory',
            packageManager: PackageManager.NPM,
            path: './myRootDirectory/mything.capra',
            versionProp: 'version'
        };
        const result = getPath(options);
        const expected = path.join(process.cwd(), './myRootDirectory/mything.capra');
        expect(result).toEqual(expected);
    });
});
