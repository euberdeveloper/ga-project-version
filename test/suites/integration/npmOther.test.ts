import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration1');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should return the version of the npm module`', function () {
        expect(getOutput()).toBe('1.0.23');
        expect(getIsError()).toBe(false);
    });
});
