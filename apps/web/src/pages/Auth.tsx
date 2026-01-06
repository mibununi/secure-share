import { useState, type FormEvent } from "react";
import { api } from "../lib/api";
import '../styles/global.css';
import '../styles/auth.css';
import { setupKeysAfterRegister } from "../lib/keySetup";
import { loadKeystore } from "../lib/keystore";

type Props = { onLoggedIn: (token: string, password: string) => void | Promise<void> };

export default function AuthPage({ onLoggedIn }: Props) {
    const [mode, setMode] = useState<"login" | "register">("login");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<string | null>(null);

    async function handleSubmit(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setMsg(null);

        try {
            const mail = email.trim();

            if (mode === "register") {
                await api.register(mail, password);
                setMsg("Registration successful. Please log in.");
                setMode("login");
                return;
            }

            const { token } = await api.login(mail, password);
            const ks = await loadKeystore();
            if (!ks) {
                await setupKeysAfterRegister(password, token);
            }
            await onLoggedIn(token, password);

            } catch (err: unknown) {
            if (err instanceof Error) {
                setMsg(err.message);
            } else {
                setMsg("Request failed");
            }
        } finally {
            setBusy(false);
        }
    }

    return (
        <div className="auth-page">
            <header className="auth-header">
                <h2>SecureShare</h2>
            </header>
                <div className="auth-wrapper">
                    <div className="auth-card">
                        <div className="tabs">
                            <button className={`tab ${mode === "login" ? "active" : ""}`} onClick={() => setMode("login")} type="button">Login</button>
                            <button className={`tab ${mode === "register" ? "active" : ""}`} onClick={() => setMode("register")} type="button">Register</button>
                        </div>

                        <form onSubmit={handleSubmit} className="form">
                            <label className="label">
                                Email
                                <input className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
                            </label>
                            <label className="label">
                                Password
                                <input className="input" type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="min 8 characters" />
                            </label>
                            <button className="btn btn--success" disabled={busy}>{busy ? "Please wait..." : (mode === "login" ? "Login" : "Create account")}</button>
                            {msg && <p className="message">{msg}</p>}
                        </form>
                    </div>
                </div>
        </div>
    );
}