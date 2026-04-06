import {useEffect, useState} from "react";
import {API_BASE} from "../lib/api";

type Project = {
    id: string;
    name: string;
    created_at: string;
    role: "admin" | "manager" | "employee";
};

type Props = {
    token: string;
    selectedProjectId: string | null;
    onSelectProject: (projectId: string | null) => void;
    onProjectsChanged?: () => void;
};

export default function ProjectsPanel({
                                          token,
                                          selectedProjectId,
                                          onSelectProject,
                                          onProjectsChanged,
                                      }: Props) {
    const [projects, setProjects] = useState<Project[]>([]);
    const [name, setName] = useState("");
    const [status, setStatus] = useState("");

    async function loadProjects() {
        try {
            setStatus("Loading projects...");
            const res = await fetch(`${API_BASE}/api/projects`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            const json = await res.json();
            if (!res.ok || !json.ok) {
                throw new Error(json?.error || "Failed to load projects");
            }

            setProjects(json.projects ?? []);
            setStatus("");
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setStatus(`Failed: ${msg}`);
        }
    }

    async function createProject(e: React.FormEvent) {
        e.preventDefault();
        try {
            const trimmed = name.trim();
            if (!trimmed) {
                setStatus("Project name is required");
                return;
            }

            setStatus("Creating project...");
            const res = await fetch(`${API_BASE}/api/projects`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({name: trimmed}),
            });

            const json = await res.json();
            if (!res.ok || !json.ok) {
                throw new Error(json?.error || "Failed to create project");
            }

            setName("");
            setStatus("Project created.");
            await loadProjects();

            if (json.project?.id) {
                onSelectProject(json.project.id);
            }

            onProjectsChanged?.();
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            setStatus(`Failed: ${msg}`);
        }
    }

    useEffect(() => {
        void loadProjects();
    }, [token]);

    return (
        <div className="panel" style={{marginTop: 16}}>
            <h3>Projects</h3>

            <form onSubmit={createProject} style={{marginTop: 12}}>
                <input
                    className="input"
                    type="text"
                    placeholder="New project name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                />
                <button
                    type="submit"
                    className="btn btn--success"
                    style={{marginTop: 8}}
                >
                    Create Project
                </button>
            </form>

            <p className="muted" style={{marginTop: 8}}>
                Status: {status || "Idle"}
            </p>

            <div style={{marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap"}}>
                <button
                    type="button"
                    className="btn"
                    onClick={() => onSelectProject(null)}
                    style={{
                        fontWeight: selectedProjectId === null ? "bold" : "normal",
                    }}
                >
                    All Files
                </button>

                {projects.map((p) => (
                    <button
                        key={p.id}
                        type="button"
                        className="btn"
                        onClick={() => onSelectProject(p.id)}
                        style={{
                            fontWeight: selectedProjectId === p.id ? "bold" : "normal",
                        }}
                        title={`Role: ${p.role}`}
                    >
                        {p.name} ({p.role})
                    </button>
                ))}
            </div>
        </div>
    );
}