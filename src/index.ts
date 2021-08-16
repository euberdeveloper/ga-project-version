import * as core from '@actions/core';

import logger from './utils/logger';
import { getPath } from './utils/getPath';
import { getVersion } from './utils/getVersion';
import { parseOptions } from './utils/parseOptions';

try {
    logger.info('Parsing options...');
    const options = parseOptions();
    logger.info('Getting path');
    const path = getPath(options);
    logger.info('Getting version', path);
    const version = getVersion(path, options.versionProp);
    logger.success('Version gotten!!!', version);
    core.setOutput('version', version);
}
catch (error) {
    console.error('Error in getting project version', error);
    core.setFailed(error.message);
}
