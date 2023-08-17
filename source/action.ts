import * as core from '@actions/core';
import logger from 'euberlog';

import { getPath } from './utils/getPath.js';
import { getVersion } from './utils/getVersion.js';
import { parseOptions } from './utils/parseOptions.js';

export default function action(): void {
    try {
        logger.info('Parsing options...');
        const options = parseOptions();
        logger.info('Getting path');
        const path = getPath(options);
        logger.info('Getting version', path);
        const version = getVersion(path, options);
        logger.success('Version gotten!!!', version);
        core.setOutput('version', version);
    } catch (error: any) {
        console.error('Error in getting project version', error);
        core.setFailed(error.message);
    }
}
