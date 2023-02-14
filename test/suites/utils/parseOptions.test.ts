import setMockActionsCoreStatus from '@test/utils/mockActionsCore.js';

import { parseOptions } from '@src/utils/parseOptions.js';
import { PackageManager } from '@src/types/Options.js';

describe('Test utility parseOptions', function () {
    it('Should work with options of status0`', function () {
        setMockActionsCoreStatus('status0');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.NPM,
            rootDirectory: '.',
            path: undefined,
            versionProp: 'version'
        });
    });

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

    it('Should work with options of status5`', function () {
        setMockActionsCoreStatus('status5');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.PIPENV,
            rootDirectory: '.',
            path: 'myjavaPath',
            versionProp: 'version'
        });
    });

    it('Should work with options of status6`', function () {
        setMockActionsCoreStatus('status6');

        const options = parseOptions();
        expect(options).toEqual({
            packageManager: PackageManager.POETRY,
            rootDirectory: '.',
            path: 'myjavaPath',
            versionProp: 'tool.poetry.version'
        });
    });

    it('Should throw an error with options of status7 because of invalid package manager`', function () {
        setMockActionsCoreStatus('status7');

        expect(() => parseOptions()).toThrow();
    });

    it('Should throw an error with options of status8 because of invalid package manager (version step)`', function () {
        setMockActionsCoreStatus('status8');

        expect(() => parseOptions()).toThrow();
    });
});
