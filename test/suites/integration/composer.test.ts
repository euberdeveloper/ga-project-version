import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration2');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should return the version of the composer module`', function () {
        expect(getOutput()).toBe('1.2.3');
        expect(getIsError()).toBe(false);
    });
});
