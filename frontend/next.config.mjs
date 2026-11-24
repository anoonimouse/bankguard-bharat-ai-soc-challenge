/** @type {import('next').NextConfig} */
const nextConfig = {
    output: process.env.NEXT_STANDALONE === "true" ? "standalone" : undefined,
    async rewrites() {
        return [
            {
                source: "/ppt",
                destination: "/ppt/index.html",
            },
        ];
    },
};

export default nextConfig;
