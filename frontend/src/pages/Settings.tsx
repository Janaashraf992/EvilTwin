import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Mail,
  Lock,
  Loader2,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  ChevronDown,
  UserCog,
} from "lucide-react";
import { useAuthStore } from "../store/authStore";
import { api } from "../api/client";
import { ThemeToggle } from "../components/shared/ThemeToggle";

export function Settings() {
  const { user } = useAuthStore();

  const [accountOpen, setAccountOpen] = useState(false);

  const [email, setEmail] = useState(user?.email ?? "");
  const [emailMsg, setEmailMsg] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [emailLoading, setEmailLoading] = useState(false);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordMsg, setPasswordMsg] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [passwordLoading, setPasswordLoading] = useState(false);

  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const handleUpdateEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailMsg(null);
    if (!email.trim()) {
      setEmailMsg({ type: "error", text: "Email cannot be empty." });
      return;
    }
    setEmailLoading(true);
    try {
      await api.patch("/auth/me", { email: email.trim() });
      setEmailMsg({ type: "success", text: "Email updated successfully." });
    } catch (err: any) {
      setEmailMsg({
        type: "error",
        text: err.response?.data?.detail ?? "Failed to update email.",
      });
    } finally {
      setEmailLoading(false);
    }
  };

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordMsg(null);
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordMsg({ type: "error", text: "All password fields are required." });
      return;
    }
    if (newPassword.length < 6) {
      setPasswordMsg({ type: "error", text: "New password must be at least 6 characters." });
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordMsg({ type: "error", text: "New passwords do not match." });
      return;
    }
    setPasswordLoading(true);
    try {
      await api.patch("/auth/me", {
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPasswordMsg({ type: "success", text: "Password updated successfully." });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      setPasswordMsg({
        type: "error",
        text: err.response?.data?.detail ?? "Failed to update password.",
      });
    } finally {
      setPasswordLoading(false);
    }
  };

  return (
    <section className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-xl p-6"
      >
        <h2 className="font-display text-2xl font-semibold">Settings</h2>
        <p className="mt-1 text-sm text-text-muted">
          Manage your account and application preferences.
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass rounded-xl"
      >
        <button
          onClick={() => setAccountOpen(!accountOpen)}
          className="w-full flex items-center justify-between p-6 hover:bg-surface/30 transition-colors rounded-xl"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <UserCog className="w-5 h-5 text-red-400" />
            </div>
            <div className="text-left">
              <h3 className="font-display text-lg font-semibold">Account</h3>
              <p className="text-xs text-text-muted">
                Change username and password
              </p>
            </div>
          </div>
          <motion.div
            animate={{ rotate: accountOpen ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronDown className="w-5 h-5 text-text-muted" />
          </motion.div>
        </button>

        <AnimatePresence>
          {accountOpen && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.25 }}
              className="overflow-hidden"
            >
              <div className="px-6 pb-6 space-y-6 border-t border-border">
                <form onSubmit={handleUpdateEmail} className="space-y-4 pt-6">
                  <h4 className="font-medium text-sm">Email / Username</h4>

                  <div>
                    <label className="block text-xs font-medium text-text-muted uppercase tracking-wider mb-1.5">
                      Email Address
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Mail className="h-4 w-4 text-text-muted" />
                      </div>
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="block w-full pl-10 pr-3 py-2.5 border border-border rounded-lg bg-surface/50 text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent transition-all text-sm"
                        placeholder="you@eviltwin.local"
                      />
                    </div>
                  </div>

                  {emailMsg && (
                    <div
                      className={`flex items-center gap-2 text-sm ${
                        emailMsg.type === "success" ? "text-safe" : "text-threat"
                      }`}
                    >
                      {emailMsg.type === "success" ? (
                        <CheckCircle className="w-4 h-4" />
                      ) : (
                        <XCircle className="w-4 h-4" />
                      )}
                      {emailMsg.text}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={emailLoading}
                    className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                  >
                    {emailLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                    Update Email
                  </button>
                </form>

                <hr className="border-border" />

                <form onSubmit={handleUpdatePassword} className="space-y-4">
                  <h4 className="font-medium text-sm">Change Password</h4>

                  <div>
                    <label className="block text-xs font-medium text-text-muted uppercase tracking-wider mb-1.5">
                      Current Password
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Lock className="h-4 w-4 text-text-muted" />
                      </div>
                      <input
                        type={showCurrent ? "text" : "password"}
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        className="block w-full pl-10 pr-10 py-2.5 border border-border rounded-lg bg-surface/50 text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent transition-all text-sm"
                        placeholder="Enter current password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrent(!showCurrent)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      >
                        {showCurrent ? (
                          <EyeOff className="h-4 w-4 text-text-muted hover:text-text-primary transition-colors" />
                        ) : (
                          <Eye className="h-4 w-4 text-text-muted hover:text-text-primary transition-colors" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-text-muted uppercase tracking-wider mb-1.5">
                        New Password
                      </label>
                      <div className="relative">
                        <input
                          type={showNew ? "text" : "password"}
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          className="block w-full px-3 pr-10 py-2.5 border border-border rounded-lg bg-surface/50 text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent transition-all text-sm"
                          placeholder="Min. 6 characters"
                        />
                        <button
                          type="button"
                          onClick={() => setShowNew(!showNew)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showNew ? (
                            <EyeOff className="h-4 w-4 text-text-muted hover:text-text-primary transition-colors" />
                          ) : (
                            <Eye className="h-4 w-4 text-text-muted hover:text-text-primary transition-colors" />
                          )}
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-text-muted uppercase tracking-wider mb-1.5">
                        Confirm Password
                      </label>
                      <div className="relative">
                        <input
                          type={showConfirm ? "text" : "password"}
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                          className="block w-full px-3 pr-10 py-2.5 border border-border rounded-lg bg-surface/50 text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent transition-all text-sm"
                          placeholder="Repeat new password"
                        />
                        <button
                          type="button"
                          onClick={() => setShowConfirm(!showConfirm)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showConfirm ? (
                            <EyeOff className="h-4 w-4 text-text-muted hover:text-text-primary transition-colors" />
                          ) : (
                            <Eye className="h-4 w-4 text-text-muted hover:text-text-primary transition-colors" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  {passwordMsg && (
                    <div
                      className={`flex items-center gap-2 text-sm ${
                        passwordMsg.type === "success" ? "text-safe" : "text-threat"
                      }`}
                    >
                      {passwordMsg.type === "success" ? (
                        <CheckCircle className="w-4 h-4" />
                      ) : (
                        <XCircle className="w-4 h-4" />
                      )}
                      {passwordMsg.text}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={passwordLoading}
                    className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                  >
                    {passwordLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                    Update Password
                  </button>
                </form>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass rounded-xl p-6 space-y-4"
      >
        <h3 className="font-display text-lg font-semibold">Appearance</h3>
        <ThemeToggle />
      </motion.div>
    </section>
  );
}
