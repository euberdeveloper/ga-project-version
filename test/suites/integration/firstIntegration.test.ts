import { setMockActionsCoreStatus, getOutput } from '@test/utils/mockActionsCore.js';
setMockActionsCoreStatus('integration0');
// TODO: euberlog does not work with ts when jest because it becomes cjs (it should pass via default)
// import '@src/index.js';

describe('Test index.ts', function () {
    it.skip('Should return the version of the npm module`', function () {
        expect(getOutput()).toBe('1.0.0');
    });
});
