"use client";

import { useRouter } from "next/navigation";
import { checkFingerprintAndRedirect } from "../app/utils";

export default function LoginButton() {
  const router = useRouter();
  return (
    <button
      className="index-login-button"
      onClick={() => checkFingerprintAndRedirect(router, "/login")}
    >
      Login
    </button>
  );
}
