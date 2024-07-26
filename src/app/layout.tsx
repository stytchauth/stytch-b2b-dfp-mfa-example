"use client";

import "./globals.css";
import "./layout.css";

import Script from "next/script";
import { ReactNode } from "react";
import Header from "../components/Header";
import StytchProvider from "../components/StytchProvider";

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <StytchProvider>
      <html lang="en">
        <title>Stytch Next.js App Router Example</title>
        <meta
          name="description"
          content="An example Next.js App Router application using Stytch for authentication"
        />
        <body>
          <Script
            src="https://elements.stytch.com/telemetry.js"
            strategy="beforeInteractive"
          />
          <div className="page-container">
            <Header />
            <main className="content-container">{children}</main>
          </div>
        </body>
      </html>
    </StytchProvider>
  );
}
