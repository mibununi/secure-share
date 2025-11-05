import { useEffect, useState } from "react";
import "./styles/global.css";
import "./styles/auth.css";
import AuthPage from "./pages/Auth";
import { api } from "./lib/api";

type Me = { id: string; email: string; public_key: string | null; created_at: string };

export default function App() {
    const [token, setToken] = useState<string | null>(() => localStorage.getItem("token"));
    const [me, setMe] = useState<Me | null>(null);
    const [status, setStatus] = useState<string>("");

    useEffect(() => {
        let cancelled = false;
        async function load() {
            if (!token) { setMe(null); return; }
            setStatus("Loading profile...");
            try {
                const { me } = await api.me(token);
                if (!cancelled) { setMe(me); setStatus(""); }
            } catch (e: any) {
                if (!cancelled) {
                    setStatus(e?.message || "Failed to load profile");
                    localStorage.removeItem("token"); setToken(null); setMe(null);
                }
            }
        }
        load();
        return () => { cancelled = true; };
    }, [token]);

    const onLoggedIn = (t: string) => { localStorage.setItem("token", t); setToken(t); };
    const logout = () => { localStorage.removeItem("token"); setToken(null); setMe(null); };

    if (!token) return <AuthPage onLoggedIn={onLoggedIn} />;

    return (
        <div className="container">
                <div className="header">
                    <h2>SecureShare</h2>
                    <button className="btn btn--danger" onClick={logout}>Logout</button>
                </div>

                {status && <p className="message">{status}</p>}

                {me && (
                    <div className="panel">
                        <div><b>User ID:</b> {me.id}</div>
                        <div><b>Email:</b> {me.email}</div>
                        <div><b>Public key:</b> {me.public_key ? "Yes" : "No"}</div>
                        <div className="muted"><b>Joined:</b> {new Date(me.created_at).toLocaleString()}</div>
                    </div>
                )}
        </div>
    );
}