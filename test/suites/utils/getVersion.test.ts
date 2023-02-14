import { getVersion } from '@src/utils/getVersion.js';
import { Options, PackageManager } from '@src/types/Options.js';

import { ASSETS_PATH } from '@test/utils/index.js';

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
});
