"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPath = void 0;
var path = require("path");
var Options_1 = require("../types/Options");
function getPackageManagerJsonName(packageManager) {
    switch (packageManager) {
        case Options_1.PackageManager.NPM:
            return "package.json";
        case Options_1.PackageManager.COMPOSER:
            return "composer.json";
    }
}
function getPath(options) {
    if (options.path) {
        return path.join(process.cwd(), options.path);
    }
    var filename = getPackageManagerJsonName(options.packageManager);
    return path.join(options.rootDirectory, filename);
}
exports.getPath = getPath;
