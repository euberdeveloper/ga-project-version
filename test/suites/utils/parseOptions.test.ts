import setMockActionsCoreStatus from '@test/utils/mockActionsCore.js';

import { parseOptions } from '@src/utils/parseOptions.js';
import { PackageManager } from '@src/types/Options.js';

describe('Test utility parseOptions', function () {
    it('Should work with options of status1`', function () {
        setMockActionsCoreStatus('status1');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.NPM,
            rootDirectory: '.',
            path: undefined,
            versionProp: 'version'
        });
    });

    it('Should work with options of status2`', function () {
        setMockActionsCoreStatus('status2');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.COMPOSER,
            rootDirectory: './composer',
            path: 'myPath',
            versionProp: 'version.myversion'
        });
    });

    it('Should work with options of status3`', function () {
        setMockActionsCoreStatus('status3');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.COMPOSER,
            rootDirectory: './composer',
            path: 'myPath',
            versionProp: 'version'
        });
    });

    it('Should work with options of status4`', function () {
        setMockActionsCoreStatus('status4');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.MAVEN,
            rootDirectory: '.',
            path: 'myjavaPath',
            versionProp: 'project.version'
        });
    });
});
