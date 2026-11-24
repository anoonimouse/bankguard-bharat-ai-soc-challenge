import type {Config} from "tailwindcss";

const config: Config = {
    content: [
        "./pages/**/*.{js,ts,jsx,tsx,mdx}", 
        "./components/**/*.{js,ts,jsx,tsx,mdx}", 
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                themeDark: '#0F172A',
                themeMid: '#2563EB',
                themeLight: '#DBEAFE',
                successGreen: '#059669',
                dangerRed: '#DC2626',
                warningYellow: '#D97706',
                themeBg: '#F8FAFC',
                sbiLightBlue: '#3b82f6', 
                sbiDarkBlue: '#0f172a',
                sbiBlue: '#1e3a8a'
            },
            backgroundImage: {
                'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))'
            }
        }
    },
    plugins: []
};
export default config;
