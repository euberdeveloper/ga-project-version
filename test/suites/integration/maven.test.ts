import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration3');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should return the version of the maven module`', function () {
        expect(getOutput()).toBe('3.1');
        expect(getIsError()).toBe(false);
    });
});
