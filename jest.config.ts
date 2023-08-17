import type { Config } from '@jest/types';
import { pathsToModuleNameMapper } from 'ts-jest';
import tsconfigJson from './tsconfig.json';

function manageKey(key: string): string {
    return key.includes('(.*)') ? key.slice(0, -1) + '\\.[cm]?js$' : key;
}
function manageMapper(mapper: Record<string, string>): Record<string, string | string[]> {
    const newMapper: Record<string, string | string[]> = {};
    for (const key in mapper) {
        newMapper[manageKey(key)] = [mapper[key], `${mapper[key]}.ts`, `${mapper[key]}.cts`, `${mapper[key]}.mts`];
    }
    newMapper['^(.*)\\.c?js$'] = ['$1', '$1.ts', '$1.cts', '$1.mts'];
    return newMapper;
}


const config: Config.InitialOptions = {
    preset: 'ts-jest/presets/default-esm',
    testEnvironment: 'jest-environment-node',
    verbose: true,
    transform: {
        '^.+\\.[cm]?tsx?$': ['ts-jest', {
            tsconfig: './tsconfig.json',
            useEsm: true
        }]
    },
    coverageProvider: 'v8',
    collectCoverageFrom: ['source/**/*.ts'],
    moduleNameMapper: manageMapper(pathsToModuleNameMapper(tsconfigJson.compilerOptions.paths, { prefix: '<rootDir>/' }) as Record<string, string>),
    transformIgnorePatterns: ['<rootDir>/node_modules/*'],
};
export default config;