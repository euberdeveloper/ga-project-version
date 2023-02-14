interface Status {
    'package-manager': string;
    'root-directory': string;
    'path': string | undefined;
    'version-prop': string | undefined;
}

const statuses = {
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
    }
};

let status: Status | null = null;

jest.mock('@actions/core', () => ({
    getInput(name: string): string | undefined {
        if (status === null) {
            throw new Error('Error in test mockup, status is null');
        }

        return status[name];
    }
}));

export default function setMockActionsCoreStatus(statusKey: keyof typeof statuses): void {
    status = statuses[statusKey];
}
