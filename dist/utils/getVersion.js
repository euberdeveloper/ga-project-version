"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getVersion = void 0;
function getVersion(path, versionProp) {
    var fileContent = require(path);
    var version = fileContent[versionProp];
    if (!version) {
        throw new Error("No version found in " + path + " within property " + versionProp);
    }
    return version;
}
exports.getVersion = getVersion;
