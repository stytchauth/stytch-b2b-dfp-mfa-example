import { useStytchB2BClient } from "@stytch/nextjs/b2b";
import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";
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
  const stytch = useStytchB2BClient();
  const router = useRouter();

  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const sendCode = async () => {
      await stytch.otps.sms.send({
        member_id,
        organization_id,
      });
    };
    if (member_id && organization_id && sendVerifyCode && !code) {
      sendCode();
    }
  }, [stytch, code, sendVerifyCode]);

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setCode(e.target.value);
    setMessage("");
  };

  const verifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await stytch.otps.sms.authenticate({
        member_id,
        organization_id,
        code,
        session_duration_minutes: 60,
      });
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
            <label htmlFor="code">Code</label>
            <input
              id="code"
              name="code"
              type="text"
              value={code}
              onChange={handleCodeChange}
              required
              autoComplete="one-time-code"
            />
          </div>
          <button type="submit" className="submit-button" disabled={isLoading}>
            {isLoading ? "Verifying..." : "Verify"}
          </button>
        </form>
        {message && <p className="message">{message}</p>}
      </div>
    </div>
  );
}
