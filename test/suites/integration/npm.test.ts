import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration0');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should return the version of the npm module`', function () {
        expect(getOutput()).toBe('1.0.0');
        expect(getIsError()).toBe(false);
    });
});
