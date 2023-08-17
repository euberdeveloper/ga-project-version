import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';

import action from '@src/action.js';

describe('Test index.ts for simple cases', function () {
    it('Should return the version of the npm module', function () {
        setMockActionsCoreStatus('integration0');
        action();
        expect(getOutput()).toBe('1.0.0');
        expect(getIsError()).toBe(false);
    });

    it('Should return the version of the composer module', function () {
        setMockActionsCoreStatus('integration1');
        action();
        expect(getOutput()).toBe('1.2.3');
        expect(getIsError()).toBe(false);
    });

    it('Should return the version of the maven module', function () {
        setMockActionsCoreStatus('integration2');
        action();
        expect(getOutput()).toBe('3.1');
        expect(getIsError()).toBe(false);
    });

    it('Should return the version of the pipenv module', function () {
        setMockActionsCoreStatus('integration3');
        action();
        expect(getOutput()).toBe('1.2.0');
        expect(getIsError()).toBe(false);
    });

    it('Should return the version of the poetry module', function () {
        setMockActionsCoreStatus('integration4');
        action();
        expect(getOutput()).toBe('1.0.3');
        expect(getIsError()).toBe(false);
    });
});
