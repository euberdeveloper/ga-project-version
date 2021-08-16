declare function __non_webpack_require__(path: string): any;

export function getVersion(path: string, versionProp: string): string {
    const fileContent = process.env.IS_WEBPACK ? __non_webpack_require__(path) : require(path);
    const version: string = fileContent[versionProp];

    if (!version) {
        throw new Error(`No version found in ${path} within property ${versionProp}`);
    }

    return version;
}