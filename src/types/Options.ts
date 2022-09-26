export enum PackageManager {
    NPM = 'npm',
    COMPOSER = 'composer',
    MAVEN = 'maven'
}

export interface Options {
    packageManager: PackageManager;
    rootDirectory: string;
    path?: string;
    versionProp: string;
}