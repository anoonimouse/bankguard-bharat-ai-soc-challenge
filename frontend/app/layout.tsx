import './globals.css'
import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import Navbar from '@/components/Navbar'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'BankGuard | Security Portal',
  description: 'Banking Protection Framework',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} text-themeDark flex flex-col min-h-screen bg-themeBg`}>
        <Navbar />
        <main className="flex-1 w-full max-w-7xl mx-auto px-3 sm:px-4 md:px-6 pt-20 sm:pt-24 pb-8 sm:pb-12 flex flex-col">
          {children}
        </main>
      </body>
    </html>
  )
}
