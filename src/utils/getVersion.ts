export function getVersion(path: string, versionProp: string): string {
    const fileContent = require(path);
    const version: string = fileContent[versionProp];

    if (!version) {
        throw new Error(`No version found in ${path} within property ${versionProp}`);
    }

    return version;
}