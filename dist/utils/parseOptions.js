"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseOptions = void 0;
var core = require("@actions/core");
var Options_1 = require("../types/Options");
function parseOptions() {
    var packageManager = core.getInput('package-manager');
    var rootDirectory = core.getInput('root-directory');
    var path = core.getInput('path');
    var versionProp = core.getInput('version-prop');
    if (!Object.values(Options_1.PackageManager).includes(packageManager)) {
        throw new Error("Invalid package manager " + packageManager);
    }
    return {
        packageManager: packageManager,
        rootDirectory: rootDirectory,
        path: path,
        versionProp: versionProp
    };
}
exports.parseOptions = parseOptions;
