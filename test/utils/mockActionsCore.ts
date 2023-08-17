import path from 'node:path';
import { ASSETS_PATH } from './paths.js';

interface Status {
    'package-manager': string;
    'root-directory': string;
    'path': string | undefined;
    'version-prop': string | undefined;
}

let status: Status | null = null;
let output: string | null = null;
let isError: boolean | null = null;

const statuses = {
    status0: {
        'package-manager': 'npm',
        'root-directory': '.',
        'path': undefined,
        'version-prop': undefined
    },
    status1: {
        'package-manager': 'npm',
        'root-directory': '.',
        'path': undefined,
        'version-prop': 'version'
    },
    status2: {
        'package-manager': 'composer',
        'root-directory': './composer',
        'path': 'myPath',
        'version-prop': 'version.myversion'
    },
    status3: {
        'package-manager': 'composer',
        'root-directory': './composer',
        'path': 'myPath',
        'version-prop': undefined
    },
    status4: {
        'package-manager': 'maven',
        'root-directory': '.',
        'path': 'myjavaPath',
        'version-prop': undefined
    },
    status5: {
        'package-manager': 'pipenv',
        'root-directory': '.',
        'path': 'myjavaPath',
        'version-prop': undefined
    },
    status6: {
        'package-manager': 'poetry',
        'root-directory': '.',
        'path': 'myjavaPath',
        'version-prop': undefined
    },
    status7: {
        'package-manager': 'invalid',
        'root-directory': '.',
        'path': 'myjavaPath',
        'version-prop': 'version'
    },
    status8: {
        'package-manager': 'invalid',
        'root-directory': '.',
        'path': 'myjavaPath',
        'version-prop': undefined
    },
    integration0: {
        'package-manager': 'npm',
        'root-directory': path.join(ASSETS_PATH, 'npm'),
        'path': undefined,
        'version-prop': undefined
    },
    integration1: {
        'package-manager': 'npm',
        'root-directory': path.join(ASSETS_PATH, 'npm-other'),
        'path': path.join(ASSETS_PATH, 'npm-other', 'deep/package.json'),
        'version-prop': 'bacucco.version'
    },
    integration2: {
        'package-manager': 'composer',
        'root-directory': path.join(ASSETS_PATH, 'composer'),
        'path': undefined,
        'version-prop': undefined
    },
    integration3: {
        'package-manager': 'maven',
        'root-directory': path.join(ASSETS_PATH, 'maven'),
        'path': undefined,
        'version-prop': undefined
    },
    integration4: {
        'package-manager': 'pipenv',
        'root-directory': path.join(ASSETS_PATH, 'pipenv'),
        'path': undefined,
        'version-prop': undefined
    },
    integration5: {
        'package-manager': 'poetry',
        'root-directory': path.join(ASSETS_PATH, 'poetry'),
        'path': undefined,
        'version-prop': undefined
    },
    integrationFails: {
        'package-manager': 'npm',
        'root-directory': path.join(ASSETS_PATH, 'npm'),
        'path': undefined,
        'version-prop': 'notExists.version'
    }
};

jest.mock('@actions/core', () => ({
    getInput(name: string): string | undefined {
        if (status === null) {
            throw new Error('Error in test mockup, status is null');
        }

        return status[name];
    },
    setOutput(_name: 'version', version: string) {
        output = version;
        isError = false;
    },
    setFailed(_message: string) {
        isError = true;
    }
}));

export function setMockActionsCoreStatus(statusKey: keyof typeof statuses): void {
    status = statuses[statusKey];
    output = null;
    isError = null;
}
export function getOutput(): string | null {
    return output;
}
export function getIsError(): boolean | null {
    return isError;
}
