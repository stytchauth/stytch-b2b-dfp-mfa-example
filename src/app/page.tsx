"use client";

import { useStytchMemberSession } from "@stytch/nextjs/b2b";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function Index() {
  const { session, isInitialized } = useStytchMemberSession();
  const router = useRouter();

  // If the Stytch SDK detects a User then redirect to profile; for example if a logged in User navigated directly to this URL.
  useEffect(() => {
    if (isInitialized && session) {
      router.replace("/dashboard");
    }
  }, [session, isInitialized, router]);

  return (
    <>
      <h1 className="index-title">DEVICE FINGERPRINTING (DFP) EXAMPLE</h1>
      <section className="index-content">
        <h2 className="index-heading">Log in to get started</h2>
        <Link href="/login" className="index-login-button">
          Log in
        </Link>
      </section>
    </>
  );
}
