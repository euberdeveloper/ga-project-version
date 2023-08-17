import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration4');
import '@src/index.js';

describe('Test index.ts', function () {
    it('Should return the version of the pipenv module`', function () {
        expect(getOutput()).toBe('1.2.0');
        expect(getIsError()).toBe(false);
    });
});
