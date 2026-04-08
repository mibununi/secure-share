export type Keystore = {
    version: 1;
    saltB64: string;
    ivB64: string;
    wrappedPrivB64: string;
    publicSpkiB64: string;
    createdAt: string;
};

const DB = "secureshare";
const STORE = "keystore";

function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB, 1);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

function makeKey(email: string) {
    return `keystore:${email.trim().toLowerCase()}`;
}

export async function saveKeystore(email: string, record: Keystore): Promise<void> {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(record, makeKey(email));
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
    db.close();
}

export async function loadKeystore(email: string): Promise<Keystore | null> {
    const db = await openDb();
    const rec = await new Promise<Keystore | null>((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const req = tx.objectStore(STORE).get(makeKey(email));
        req.onsuccess = () => resolve((req.result as Keystore) || null);
        req.onerror = () => reject(req.error);
    });
    db.close();
    return rec;
}