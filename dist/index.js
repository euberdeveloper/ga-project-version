"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core = require("@actions/core");
var logger_1 = require("utils/logger");
var getPath_1 = require("utils/getPath");
var getVersion_1 = require("utils/getVersion");
var parseOptions_1 = require("utils/parseOptions");
try {
    logger_1.default.info('Parsing options...');
    var options = parseOptions_1.parseOptions();
    logger_1.default.info('Getting path');
    var path = getPath_1.getPath(options);
    logger_1.default.info('Getting version', path);
    var version = getVersion_1.getVersion(path, options.versionProp);
    logger_1.default.success('Version gotten!!!', version);
    core.setOutput('version', version);
}
catch (error) {
    console.error('Error in getting project version', error);
    core.setFailed(error.message);
}
