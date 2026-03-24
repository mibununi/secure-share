export const mockFilesLedger = {
    getACL: jest.fn(async () => []),
    createFile: jest.fn(async () => undefined),
    grantAccess: jest.fn(async () => undefined),
    revokeAccess: jest.fn(async () => undefined),
    getAudit: jest.fn(async () => []),
    ping: jest.fn(async () => "ok"),
};

export const getFilesLedger = jest.fn(async () => mockFilesLedger);