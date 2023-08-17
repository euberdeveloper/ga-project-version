import { setMockActionsCoreStatus, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integrationFails');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should be errored and set is Error to true', function () {
        expect(getIsError()).toBe(true);
    });
});
