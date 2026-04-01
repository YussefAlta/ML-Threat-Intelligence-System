"use client";

import { IntelligenceProvider } from "@/context/IntelligenceContext";
import { Sidebar } from "@/components/Sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <IntelligenceProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="flex-1 ml-64 p-8 overflow-x-hidden">{children}</main>
      </div>
    </IntelligenceProvider>
  );
}
