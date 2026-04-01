"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Shield,
  BarChart3,
  Network,
  FlaskConical,
  ShieldAlert,
  Bell,
  Share2,
} from "lucide-react";
import { useIntelligence } from "@/context/IntelligenceContext";

const navItems = [
  { href: "/overview", label: "Command center", icon: LayoutDashboard },
  { href: "/graph", label: "Entity graph", icon: Share2 },
  { href: "/alerts", label: "Alerts", icon: Bell, showBadge: true },
  { href: "/threats", label: "Threats", icon: ShieldAlert },
  { href: "/analytics", label: "Analytics", icon: BarChart3 },
  { href: "/entities", label: "Entities", icon: Network },
  { href: "/evaluation", label: "Evaluation", icon: FlaskConical },
];

export function Sidebar() {
  const pathname = usePathname();
  const { activeAlertCount } = useIntelligence();

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-slate-900 border-r border-slate-800/50 flex flex-col z-50">
      {/* Logo / Title */}
      <div className="p-6 border-b border-slate-800/50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center glow-cyan">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 tracking-wide">
              AVINT
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest">
              Threat Intelligence
            </p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href === "/overview" && pathname === "/");
          const Icon = item.icon;
          const showBadge =
            "showBadge" in item &&
            item.showBadge &&
            activeAlertCount > 0;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent"
              }`}
            >
              <Icon
                className={`w-[18px] h-[18px] transition-colors ${
                  isActive
                    ? "text-cyan-400"
                    : "text-slate-500 group-hover:text-slate-300"
                }`}
              />
              <span className="flex-1">{item.label}</span>
              {showBadge && (
                <span className="text-[10px] font-bold min-w-[1.25rem] h-5 px-1 rounded-full bg-amber-500/25 text-amber-400 border border-amber-500/40 flex items-center justify-center">
                  {activeAlertCount > 99 ? "99+" : activeAlertCount}
                </span>
              )}
              {isActive && !showBadge && (
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(6,182,212,0.6)]" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800/50">
        <div className="px-3 py-2">
          <p className="text-[10px] text-slate-600 uppercase tracking-widest">
            Pipeline Status
          </p>
          <div className="flex items-center gap-2 mt-1.5">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)] animate-pulse" />
            <span className="text-xs text-slate-400">Operational</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
