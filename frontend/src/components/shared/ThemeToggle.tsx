import { Sun, Moon } from "lucide-react";
import { useThemeStore } from "../../store/themeStore";

export function ThemeToggle() {
  const { theme, toggleTheme } = useThemeStore();

  return (
    <button
      onClick={toggleTheme}
      className="relative flex items-center gap-3 px-4 py-3 rounded-xl border border-border bg-surface/50 hover:bg-surface transition-all duration-300 group"
    >
      <div className="flex items-center gap-2">
        {theme === "dark" ? (
          <Moon className="w-5 h-5 text-text-muted group-hover:text-text-primary transition-colors" />
        ) : (
          <Sun className="w-5 h-5 text-text-muted group-hover:text-text-primary transition-colors" />
        )}
        <span className="text-sm font-medium text-text-primary">
          {theme === "dark" ? "Dark Mode" : "Light Mode"}
        </span>
      </div>
      <div
        className={`ml-auto w-10 h-5 rounded-full relative transition-colors duration-300 ${
          theme === "dark" ? "bg-red-500" : "bg-slate-300"
        }`}
      >
        <div
          className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-300 ${
            theme === "dark" ? "translate-x-5" : "translate-x-0.5"
          }`}
        />
      </div>
    </button>
  );
}
