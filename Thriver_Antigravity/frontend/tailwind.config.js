/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['"Outfit"', '"Space Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
        cyber: ['"Outfit"', '"Space Grotesk"', 'sans-serif'],
      },
      colors: {
        soc: {
          bg: '#0a0d14',
          panel: '#121824',
          border: '#1f293d',
          accent: '#3b82f6',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          success: '#10b981'
        },
        glass: {
          stroke: 'rgba(255, 255, 255, 0.12)',
          highlight: 'rgba(255, 255, 255, 0.22)',
          surface: 'rgba(18, 24, 38, 0.70)',
        }
      }
    },
  },
  plugins: [],
}
