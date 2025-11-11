export default function() {
    return {
        pinFileToIPFS: async () => ({
            IpfsHash: "bafybeigdyrandomcidfor-tests",
            PinSize: 123,
            Timestamp: new Date().toISOString(),
        }),
    };
}
