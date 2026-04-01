/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          50:  '#edfcff',
          100: '#d6f7ff',
          200: '#b5f2ff',
          300: '#83ebff',
          400: '#48dafb',
          500: '#1ebef2',
          600: '#069cd0',
          700: '#077ca9',
          800: '#0c648a',
          900: '#105373',
          950: '#07354f',
        },
        threat: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#eab308',
          low:      '#3b82f6',
          info:     '#6b7280',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in':   'slideIn 0.3s ease-out',
        'fade-in':    'fadeIn 0.4s ease-out',
      },
      keyframes: {
        slideIn: {
          '0%':   { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)',     opacity: '1' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
