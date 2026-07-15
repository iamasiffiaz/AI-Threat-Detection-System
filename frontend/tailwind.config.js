/** @type {import('tailwindcss').Config} */
/**
 * HCI-informed SaaS palette:
 * - Layered surfaces for figure–ground hierarchy (canvas → panel → card)
 * - Trust blue as brand (long-session calm; clearer than neon cyan)
 * - Semantic severity kept distinct from brand accents
 * - Soft elevation instead of neon glow (lower visual fatigue)
 */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0B1220',
          panel: '#121A2B',
          card: '#182234',
          elevated: '#1E2A3F',
          border: '#2A3548',
          cyan: '#3B82F6',
          blue: '#2563EB',
          text: '#F1F5F9',
          muted: '#A8B3C7',
          faint: '#7B879C',
        },
        // Brand scale (kept as "cyber" for class compatibility → professional blue)
        cyber: {
          50:  '#EFF6FF',
          100: '#DBEAFE',
          200: '#BFDBFE',
          300: '#93C5FD',
          400: '#60A5FA',
          500: '#3B82F6',
          600: '#2563EB',
          700: '#1D4ED8',
          800: '#1E40AF',
          900: '#1E3A8A',
          950: '#172554',
        },
        threat: {
          critical: '#EF4444',
          high:     '#F97316',
          medium:   '#EAB308',
          low:      '#22C55E',
          info:     '#64748B',
        },
      },
      fontFamily: {
        display: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in':   'slideIn 0.25s ease-out',
        'fade-in':    'fadeIn 0.35s ease-out',
      },
      keyframes: {
        slideIn: {
          '0%':   { transform: 'translateY(4px)', opacity: '0' },
          '100%': { transform: 'translateY(0)',   opacity: '1' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
      boxShadow: {
        'cyan-glow': '0 1px 2px rgba(0,0,0,0.2), 0 8px 24px rgba(15, 23, 42, 0.45)',
        'crit-glow': '0 0 0 1px rgba(239, 68, 68, 0.25), 0 8px 20px rgba(239, 68, 68, 0.12)',
        card: '0 1px 2px rgba(0,0,0,0.18), 0 10px 28px rgba(0,0,0,0.28)',
        focus: '0 0 0 3px rgba(59, 130, 246, 0.35)',
      },
      borderRadius: {
        xl: '0.875rem',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
