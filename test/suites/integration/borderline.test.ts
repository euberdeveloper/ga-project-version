import { setMockActionsCoreStatus, getOutput, getIsError } from '@test/utils/mockActionsCore.js';

import action from '@src/action.js';

describe('Test index.ts for borderline cases', function () {
    it('Should return the version of the npm module even if in a deep property and in a deep folder', function () {
        setMockActionsCoreStatus('integrationDeep');
        action();
        expect(getOutput()).toBe('1.0.23');
        expect(getIsError()).toBe(false);
    });
});
