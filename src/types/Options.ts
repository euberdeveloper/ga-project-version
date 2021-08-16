export enum PackageManager {
    NPM = 'npm',
    COMPOSER = 'composer'
}

export interface Options {
    packageManager: PackageManager;
    rootDirectory: string;
    path?: string;
    versionProp: string;
}