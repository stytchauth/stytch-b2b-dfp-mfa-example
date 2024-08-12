"use client";
import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";
import {
  addKnownDeviceAfterVerify,
  sendSMSCode,
  verifySMSCode,
} from "../app/actions";
import "./VerifySMSMFA.css";

interface VerifySMSMFAProps {
  sendVerifyCode?: boolean;
  member_id: string;
  organization_id: string;
}

export default function VerifySMSMFA({
  sendVerifyCode,
  member_id,
  organization_id,
}: VerifySMSMFAProps) {
  const router = useRouter();

  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const sendCode = async () => {
      try {
        await sendSMSCode(member_id, organization_id);
      } catch (error) {
        console.error("Error sending SMS code:", error);
        setMessage("Error sending verification code. Please try again.");
      }
    };
    if (member_id && organization_id && sendVerifyCode && !code) {
      sendCode();
    }
  }, [member_id, organization_id, sendVerifyCode, code]);

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setCode(e.target.value);
    setMessage("");
  };

  const verifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await verifySMSCode(member_id, organization_id, code);
      addKnownDeviceAfterVerify();
      setMessage("MFA authentication successful!");
      router.push("/dashboard");
    } catch (error) {
      console.error("Error authenticating MFA:", error);
      setMessage("Error authenticating. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-content">
        <h2 className="login-title">
          Enter the 6-digit code sent to your phone
        </h2>
        <form onSubmit={verifyCode} className="login-form">
          <div className="form-group">
            <label htmlFor="code">Verification Code</label>
            <input
              id="code"
              name="code"
              type="text"
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              value={code}
              onChange={handleCodeChange}
              required
              autoComplete="one-time-code"
              aria-describedby="code-description"
            />
            <small id="code-description">
              Enter the 6-digit code you received via SMS
            </small>
          </div>
          <button type="submit" className="submit-button" disabled={isLoading}>
            {isLoading ? "Verifying..." : "Verify"}
          </button>
        </form>
        {message && (
          <p className="message" role="alert">
            {message}
          </p>
        )}
      </div>
    </div>
  );
}
