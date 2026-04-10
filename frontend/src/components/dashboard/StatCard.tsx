import { ReactNode } from "react";
import { motion } from "framer-motion";

export function StatCard({ label, value, icon }: { label: string; value: string | number; icon?: ReactNode }) {
  return (
    <motion.article 
      whileHover={{ y: -4, scale: 1.02, boxShadow: "0 10px 30px -10px rgba(46, 196, 182, 0.2)" }} 
      transition={{ ease: "easeOut", duration: 0.2 }}
      className="glass-elevated rounded-xl p-5 border-white/5 hover:border-safe/30 transition-colors cursor-default group relative overflow-hidden"
    >
      <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-white">
        {icon}
      </div>
      <div className="flex justify-between items-start">
        <p className="text-xs uppercase tracking-widest text-text-muted font-display font-semibold group-hover:text-safe transition-colors z-10">{label}</p>
        <div className="text-text-muted/80 group-hover:text-safe/80 transition-colors z-10">
          {icon}
        </div>
      </div>
      <p className="mt-3 text-4xl font-display font-bold text-text-primary group-hover:text-white transition-colors tracking-tight z-10">{value}</p>
    </motion.article>
  );
}
