import { setMockActionsCoreStatus, getIsError } from '@test/utils/mockActionsCore.js';

import action from '@src/action.js';

describe('Test index.ts for failing cases', function () {
    it('Should be errored and set is Error to true', function () {
        setMockActionsCoreStatus('integrationFails');
        action();
        expect(getIsError()).toBe(true);
    });
});
