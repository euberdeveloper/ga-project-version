export enum PackageManager {
    NPM = 'npm',
    COMPOSER = 'composer',
    MAVEN = 'maven',
    PIPENV = 'pipenv',
    POETRY = 'poetry'
}

export interface Options {
    packageManager: PackageManager;
    rootDirectory: string;
    path?: string;
    versionProp: string;
}