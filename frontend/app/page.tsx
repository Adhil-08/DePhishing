"use client";

import { useState } from "react";

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<any>(null);

  const investigate = async () => {
  if (!input.trim()) return;

  try {
    const response = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: input.trim(),
      }),
    });

    const data = await response.json();

    setResult(data);
  } catch (error) {
    console.error("Backend connection error:", error);

    setResult({
      error: "Could not connect to CyberSleuth backend.",
    });
  }
};

  return (
    <main className="min-h-screen bg-slate-950 text-white">
      
      {/* Header */}
      <header className="border-b border-slate-800">
        <div className="mx-auto max-w-6xl px-6 py-5">
          <h1 className="text-3xl font-bold text-cyan-400">
            CyberSleuth
          </h1> 
                   <p className="mt-1 text-slate-400">
            AI-Powered Phishing Detector
          </p>
        </div>
      </header>

      {/* Main Content */}
      <section className="mx-auto max-w-4xl px-6 py-16">

        {/* Introduction */}
        <div className="text-center">
          <h2 className="text-4xl font-bold">
            Investigate Suspicious Content
          </h2>

          <p className="mt-4 text-slate-400">
            Analyze a suspicious URL or message and identify potential
            phishing threats.
          </p>
        </div>

        {/* Input Card */}
        <div className="mt-10 rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">

          <label className="mb-3 block text-sm font-medium text-slate-300">
            URL or Message
          </label>

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste a suspicious URL or message here..."
            className="min-h-40 w-full resize-none rounded-xl border border-slate-700 bg-slate-950 p-4 text-white outline-none placeholder:text-slate-600 focus:border-cyan-400"
          />

          <button
            onClick={investigate}
            className="mt-5 w-full rounded-xl bg-cyan-500 px-6 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400"
          >
            🔍 Investigate
          </button>
        </div>

        {/* Result */}
        {result && (
          <div className="mt-8 rounded-2xl border border-red-500/30 bg-slate-900 p-6 shadow-xl">

            <h2 className="text-2xl font-bold text-cyan-400">
              Investigation Result
            </h2>

            <p className="mt-4 text-sm text-slate-400">
              Analyzed input:
            </p>

            <p className="mt-2 break-words rounded-lg bg-slate-950 p-4 text-slate-200">
              {result}
            </p>

            {/* Temporary Risk Result */}
            <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 p-5">
              <p className="text-sm text-slate-400">
                Risk Level
              </p>

              <p className="mt-1 text-3xl font-bold text-red-400">
                HIGH
              </p>

              <p className="mt-3 text-slate-300">
                This is a temporary demo result. The actual CyberSleuth
                analysis will come from the backend later.
              </p>
            </div>

          </div>
        )}

      </section>
    </main>
  );
}