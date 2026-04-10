import { useLocation, Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { 
  LayoutDashboard, 
  Activity, 
  ShieldAlert,
  Settings,
  Shield,
  LogOut
} from "lucide-react";
import { useAuthStore } from "../../store/authStore";

const navItems = [
  { path: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { path: "/sessions", label: "Sessions", icon: Activity },
  { path: "/threat-intel", label: "Threat Intel", icon: ShieldAlert },
  { path: "/settings", label: "Settings", icon: Settings }
];

export function Sidebar() {
  const { logout } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside className="hidden md:flex flex-col w-[260px] h-screen bg-black/40 backdrop-blur-xl border-r border-white/5 p-6 sticky top-0">
      {/* Brand */}
      <div className="flex items-center gap-3 mb-12">
        <div className="p-2 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-xl border border-red-500/20">
          <Shield className="w-6 h-6 text-red-500" />
        </div>
        <div>
          <h1 className="font-bold text-lg tracking-wide text-white">EvilTwin</h1>
          <p className="text-[10px] uppercase tracking-wider text-white/40 font-medium">SOC Platform</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-2">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          const Icon = item.icon;

          return (
            <Link
              key={item.path}
              to={item.path}
              className={`
                relative flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300
                ${isActive 
                  ? "text-white bg-white/10 shadow-[inset_0_1px_0_rgba(255,255,255,0.1)]" 
                  : "text-white/50 hover:text-white hover:bg-white/5"}
              `}
            >
              {isActive && (
                <motion.div
                  layoutId="sidebar-active"
                  className="absolute inset-0 bg-gradient-to-r from-red-500/10 to-transparent rounded-xl border border-white/10"
                  transition={{ type: "spring", stiffness: 300, damping: 30 }}
                />
              )}
              <Icon className={`w-5 h-5 relative z-10 ${isActive ? "text-red-400" : ""}`} />
              <span className="font-medium text-sm relative z-10">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer System Status */}
      <div className="mt-8 pt-8 border-t border-white/5 space-y-4">
        <div className="p-4 rounded-xl bg-white/5 border border-white/5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-wider">System Status</span>
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-white/40">Honeypots</span>
              <span className="text-emerald-400 font-medium font-mono">3 Online</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-white/40">AI Engine</span>
              <span className="text-emerald-400 font-medium font-mono">Active</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-white/40">SDN Controller</span>
              <span className="text-emerald-400 font-medium font-mono">Synced</span>
            </div>
          </div>
        </div>

        {/* Logout Button */}
        <button
          onClick={handleLogout}
          className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-white/50 hover:text-white hover:bg-white/5 hover:border-white/10 border border-transparent transition-all duration-300 group"
        >
          <LogOut className="w-4 h-4 group-hover:text-red-400 transition-colors" />
          <span className="text-sm font-medium">Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
