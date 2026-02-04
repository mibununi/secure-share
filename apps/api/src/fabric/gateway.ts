import * as fs from 'fs';
import * as path from 'path';
import { connect, signers, type Gateway, type Identity } from '@hyperledger/fabric-gateway';
import * as grpc from '@grpc/grpc-js';

function mustEnv(name: string): string {
    const v = process.env[name];
    if (!v || v.trim() === '') throw new Error(`Missing env var: ${name}`);
    return v;
}

function firstPeerFromConnectionProfile(ccp: any): { endpoint: string; tlsPem: Buffer } {
    const peers = ccp?.peers;
    if (!peers || typeof peers !== 'object') {
        throw new Error('Invalid connection profile: missing peers');
    }
    const peerName = Object.keys(peers)[0];
    if (!peerName) throw new Error('Connection profile has no peers');

    const p = peers[peerName];
    const url: string = p?.url;
    if (!url) throw new Error(`Peer ${peerName} missing url in connection profile`);

    const endpoint = url.replace(/^grpcs?:\/\//, '');
    const tlsPemB64: string | undefined = p?.tlsCACerts?.pem;
    const tlsPem =
        tlsPemB64 && tlsPemB64.includes('BEGIN CERTIFICATE')
            ? Buffer.from(tlsPemB64)
            : Buffer.from(tlsPemB64 ?? '');

    return { endpoint, tlsPem };
}

export type FabricConfig = {
    channelName: string;
    chaincodeName: string;
};

export async function newGateway(cfg: FabricConfig): Promise<{ gateway: Gateway }> {
    const ccpPath = path.resolve(mustEnv('FABRIC_CCP_PATH'));
    const certPath = path.resolve(mustEnv('FABRIC_CERT_PATH'));
    const keyPath = path.resolve(mustEnv('FABRIC_KEY_PATH'));
    const peerTlsCaPath = path.resolve(mustEnv('FABRIC_PEER_TLS_CA_PATH'));

    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    // peer endpoint
    const { endpoint } = firstPeerFromConnectionProfile(ccp);

    // TLS root cert for the peer connection
    const tlsRootCert = fs.readFileSync(peerTlsCaPath);

    const client = new grpc.Client(
        endpoint,
        grpc.credentials.createSsl(tlsRootCert)
    );

    // identity
    const certPem = fs.readFileSync(certPath).toString();
    const identity: Identity = {
        mspId: mustEnv('FABRIC_MSP_ID'),
        credentials: Buffer.from(certPem),
    };

    // signer (private key)
    const privateKeyPem = fs.readFileSync(keyPath);
    const signer = signers.newPrivateKeySigner(privateKeyPem);

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