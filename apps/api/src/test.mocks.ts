jest.mock("./fabric/gateway", () => require("./__mocks__/fabricGateway"));

jest.mock("./utils/access", () => {
    const actual = jest.requireActual("./utils/access");
    const mocked = require("./__mocks__/access");

    return {
        ...actual,
        requireFileAccessOrOwner: mocked.requireFileAccessOrOwner,
    };
});