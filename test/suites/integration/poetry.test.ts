import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration5');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should return the version of the poetry module`', function () {
        expect(getOutput()).toBe('1.0.3');
        expect(getIsError()).toBe(false);
    });
});
