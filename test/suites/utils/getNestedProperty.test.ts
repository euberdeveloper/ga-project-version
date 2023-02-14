import { getNestedProperty } from '@src/utils/getNestedProperty.js'

describe('Test utility getNestedProperty', function () {
    it('Should work with a flat key`', function () {
        const object = {
            'key': 'value'
        };
        const result = getNestedProperty(object, 'key');
        const expected = 'value';
        expect(result).toEqual(expected);
    });

    it('Should work with another flat key`', function () {
        const object = {
            'anotherKey': 'anotherValue'
        };
        const result = getNestedProperty(object, 'anotherKey');
        const expected = 'anotherValue';
        expect(result).toEqual(expected);
    });

    it('Should work with a second-level key`', function () {
        const object = {
            'key': {
                'nestedKey': 'nestedValue'
            }
        };
        const result = getNestedProperty(object, 'key.nestedKey');
        const expected = 'nestedValue';
        expect(result).toEqual(expected);
    });

    it('Should work with a third-level key`', function () {
        const object = {
            'key': {
                'nestedKey': {
                    'nestedKey': 'nestedValue'
                }
            }
        };
        const result = getNestedProperty(object, 'key.nestedKey.nestedKey');
        const expected = 'nestedValue';
        expect(result).toEqual(expected);
    });

    it('Should work with a number value`', function () {
        const object = {
            'key': {
                'nestedKey': {
                    'nestedKey': 23
                }
            }
        };
        const result = getNestedProperty(object, 'key.nestedKey.nestedKey');
        const expected = 23;
        expect(result).toEqual(expected);
    });

    it('Should return undefined if the key does not exist', function () {
        const object = {
            'key': {
                'nestedKey': {
                    'nestedKey': 23
                }
            }
        };
        const result = getNestedProperty(object, 'key.nestedKey.doesNotExist.nestedKey');
        const expected = undefined;
        expect(result).toEqual(expected);
    });
});
