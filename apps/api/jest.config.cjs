/** @type {import('jest').Config} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    // look for tests under src by default
    roots: ['<rootDir>/src'],
    // load test env AFTER Jest is ready (so imports work)
    setupFilesAfterEnv: ['<rootDir>/src/test.setup.ts'],
    transform: {
        '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }],
    },
};