import * as fs from 'fs';
import * as path from 'path';
import { connect, signers, type Gateway, type Identity } from '@hyperledger/fabric-gateway';
import * as grpc from '@grpc/grpc-js';
import { createPrivateKey } from "crypto";
import { FilesLedger } from "./filesLedger";

function mustEnv(name: string): string {
    const v = process.env[name];
    if (!v || v.trim() === '') throw new Error(`Missing env var: ${name}`);
    return v;
}

function loadTlsRootCert(ccp: any, peerName: string): Buffer {
    // prefer explicit env var file
    const caPath = process.env.FABRIC_PEER_TLS_CA_PATH;
    if (caPath && caPath.trim() !== "") {
        return fs.readFileSync(path.resolve(caPath));
    }

    // fallback to embedded PEM in connection profile
    const pem = ccp?.peers?.[peerName]?.tlsCACerts?.pem;
    if (!pem || typeof pem !== "string" || !pem.includes("BEGIN CERTIFICATE")) {
        throw new Error(`Missing TLS CA: set FABRIC_PEER_TLS_CA_PATH or provide tlsCACerts.pem for peer ${peerName}`);
    }
    return Buffer.from(pem, "utf8");
}

function firstPeerFromConnectionProfile(ccp: any): { peerName: string; endpoint: string } {
    const peers = ccp?.peers;
    if (!peers || typeof peers !== "object") throw new Error("Invalid connection profile: missing peers");

    const peerName = Object.keys(peers)[0];
    if (!peerName) throw new Error("Connection profile has no peers");

    const p = peers[peerName];
    const url: string = p?.url;
    if (!url) throw new Error(`Peer ${peerName} missing url in connection profile`);

    const endpoint = url.replace(/^grpcs?:\/\//, "");
    return { peerName, endpoint };
}

export type FabricConfig = {
    channelName: string;
    chaincodeName: string;
};

export async function newGateway(cfg: FabricConfig): Promise<{ gateway: Gateway }> {
    const ccpPath = path.resolve(mustEnv('FABRIC_CCP_PATH'));
    const certPath = path.resolve(mustEnv('FABRIC_CERT_PATH'));
    const keyPath = path.resolve(mustEnv('FABRIC_KEY_PATH'));

    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    // peer endpoint
    const { peerName, endpoint } = firstPeerFromConnectionProfile(ccp);

    // TLS root cert for the peer connection
    const tlsRootCert = loadTlsRootCert(ccp, peerName);

    const tlsHost =
        ccp?.peers?.[peerName]?.grpcOptions?.["ssl-target-name-override"] ||
        "peer0.org1.example.com";

    const client = new grpc.Client(
        endpoint,
        grpc.credentials.createSsl(tlsRootCert),
        {
            "grpc.ssl_target_name_override": tlsHost,
            "grpc.default_authority": tlsHost,
        }
    );

    // identity
    const certPem = fs.readFileSync(certPath).toString();
    const identity: Identity = {
        mspId: mustEnv('FABRIC_MSP_ID'),
        credentials: Buffer.from(certPem),
    };

    // signer (private key)
    const privateKeyPem = fs.readFileSync(keyPath);
    const privateKey = createPrivateKey(privateKeyPem);
    const signer = signers.newPrivateKeySigner(privateKey);

    const gateway = connect({
        client,
        identity,
        signer,
        // defaults for dev
        evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
        endorseOptions: () => ({ deadline: Date.now() + 15000 }),
        submitOptions: () => ({ deadline: Date.now() + 15000 }),
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });

    return { gateway };
}

export async function getFilesLedger(): Promise<FilesLedger> {
    const channelName = mustEnv("FABRIC_CHANNEL");
    const chaincodeName = mustEnv("FABRIC_CHAINCODE");

    const { gateway } = await newGateway({ channelName, chaincodeName });
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    return new FilesLedger(contract);
}