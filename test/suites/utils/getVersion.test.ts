import { getVersion } from '@src/utils/getVersion.js';
import { Options, PackageManager } from '@src/types/Options.js';

import { ASSETS_PATH } from '@test/utils/paths.js';

import path from 'node:path';

describe('Test utility getVersion', function () {
    it('Should work with an npm project`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'npm'),
            packageManager: PackageManager.NPM,
            versionProp: 'version'
        };
        const result = getVersion(`${options.rootDirectory}/package.json`, options);
        const expected = '1.0.0';
        expect(result).toEqual(expected);
    });

    it('Should work with another npm project`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'npm-other', 'deep'),
            packageManager: PackageManager.NPM,
            versionProp: 'bacucco.version'
        };
        const result = getVersion(`${options.rootDirectory}/package.json`, options);
        const expected = '1.0.23';
        expect(result).toEqual(expected);
    });

    it('Should work with a maven project`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'maven'),
            packageManager: PackageManager.MAVEN,
            versionProp: 'project.version'
        };
        const result = getVersion(`${options.rootDirectory}/pom.xml`, options);
        const expected = '3.1';
        expect(result).toEqual(expected);
    });

    it('Should work with a poetry project`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'poetry'),
            packageManager: PackageManager.POETRY,
            versionProp: 'tool.poetry.version'
        };
        const result = getVersion(`${options.rootDirectory}/pyproject.toml`, options);
        const expected = '1.0.3';
        expect(result).toEqual(expected);
    });

    it('Should work with a Pipenv project`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'pipenv'),
            packageManager: PackageManager.PIPENV,
            versionProp: 'version'
        };
        const result = getVersion(`${options.rootDirectory}/Pipfile`, options);
        const expected = '1.2.0';
        expect(result).toEqual(expected);
    });

    it('Should throw an error because version is not present`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'pipenv'),
            packageManager: PackageManager.PIPENV,
            versionProp: 'wrong'
        };
        expect(() => getVersion(`${options.rootDirectory}/Pipfile`, options)).toThrow();
    });

    it('Should throw an error because of invalid packageManager`', function () {
        const options: Options = {
            rootDirectory: path.join(ASSETS_PATH, 'pipenv'),
            packageManager: 'pocca' as any,
            versionProp: 'version'
        };
        expect(() => getVersion(`${options.rootDirectory}/Pipfile`, options)).toThrow();
    });
});
