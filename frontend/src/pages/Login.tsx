import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { Lock, Mail, Loader2, ShieldAlert } from "lucide-react";
import { useAuthStore } from "../store/authStore";
import { api } from "../api/client";

const SHOWCASE_MODE = import.meta.env.VITE_SHOWCASE_MODE === 'true';

export const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { setAuth } = useAuthStore();

  const from = location.state?.from?.pathname || "/dashboard";

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      if (SHOWCASE_MODE) {
        // Mock showcase login
        if (email === "admin@eviltwin.local" && password === "admin") {
          setAuth(
            { id: "00000000-0000-0000-0000-000000000000", email: "admin@eviltwin.local" },
            "mock-access-token",
            "mock-refresh-token"
          );
          navigate(from, { replace: true });
          return;
        } else {
          throw new Error("Invalid showcase credentials. Use admin@eviltwin.local / admin");
        }
      }

      const formData = new URLSearchParams();
      formData.append("username", email);
      formData.append("password", password);

      const response = await api.post("/auth/login", formData, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });

      const { access_token, refresh_token } = response.data;
      
      const userRes = await api.get("/auth/me", {
        headers: { Authorization: `Bearer ${access_token}` }
      });

      setAuth(userRes.data, access_token, refresh_token);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to authenticate. Please check your credentials.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background gradients and elements similar to the dashboard */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-red-900/20 blur-[120px]" />
        <div className="absolute bottom-[-20%] right-[-10%] w-[60%] h-[60%] rounded-full bg-indigo-900/10 blur-[150px]" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="bg-white/5 border border-white/10 rounded-2xl p-8 backdrop-blur-xl relative shadow-2xl">
          <div className="flex justify-center mb-8">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500/20 to-orange-500/20 flex items-center justify-center border border-white/10 shadow-[0_0_30px_rgba(239,68,68,0.3)]">
              <ShieldAlert className="w-8 h-8 text-red-500" />
            </div>
          </div>
          
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-white to-white/60 bg-clip-text text-transparent">
              EvilTwin SOC
            </h1>
            <p className="text-white/40 mt-2 text-sm">Sign in to access the threat dashboard</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            {error && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm text-center font-medium"
              >
                {error}
              </motion.div>
            )}

            <div className="space-y-1">
              <label className="text-xs font-medium text-white/40 uppercase tracking-wider pl-1">Email</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-white/30" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="block w-full pl-10 pr-3 py-3 border border-white/10 rounded-xl leading-5 bg-white/5 text-white placeholder-white/20 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent transition-all sm:text-sm"
                  placeholder="admin@eviltwin.local"
                  required
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-medium text-white/40 uppercase tracking-wider pl-1">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-white/30" />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-3 py-3 border border-white/10 rounded-xl leading-5 bg-white/5 text-white placeholder-white/20 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent transition-all sm:text-sm"
                  placeholder={SHOWCASE_MODE ? "admin" : "••••••••"}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full relative flex items-center justify-center space-x-2 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white p-3 rounded-xl font-medium tracking-wide shadow-[0_0_20px_rgba(220,38,38,0.4)] transition-all disabled:opacity-50 disabled:cursor-not-allowed overflow-hidden mt-6"
            >
              <div className="absolute inset-0 bg-white/20 translate-y-[-100%] transition-transform group-hover:translate-y-0" />
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <span>Authenticate</span>
              )}
            </button>
          </form>
        </div>
      </motion.div>
    </div>
  );
};
