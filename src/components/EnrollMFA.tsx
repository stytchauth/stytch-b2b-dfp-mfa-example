"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import React, { useState } from "react";
import { sendSMSCode } from "../app/actions";
import "./VerifySMSMFA.css";

interface EnrollMFAProps {
  memberId: string;
  organizationId: string;
}

export default function EnrollMFA({
  memberId,
  organizationId,
}: EnrollMFAProps) {
  const router = useRouter();
  const [phoneNumber, setPhoneNumber] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState("");
  const handlePhoneNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPhoneNumber(e.target.value);
    setMessage("");
  };

  const sendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await sendSMSCode(memberId, organizationId, phoneNumber);
      router.push("/verify");
      setMessage("Code sent successfully. Please check your phone.");
    } catch (error) {
      console.error("Error sending code:", error);
      setMessage("Error sending code. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-content">
        <h2 className="login-title">Enroll in MFA</h2>
        <p>
          Or <Link href="/dashboard">skip this step</Link>
        </p>
        <form
          onSubmit={sendCode}
          className="login-form"
          aria-label="Enroll in MFA"
        >
          <div className="form-group">
            <label htmlFor="phone-number">
              Enter your phone number to set up Multi-Factor Authentication
            </label>
            <input
              id="phone-number"
              type="tel"
              pattern="^\+[1-9]\d{1,14}$"
              placeholder="+1234567890"
              value={phoneNumber}
              onChange={handlePhoneNumberChange}
              required
            />
          </div>
          <button type="submit" className="submit-button" disabled={isLoading}>
            {isLoading ? "Sending..." : "Send Code"}
          </button>
        </form>
        {message && <p className="message">{message}</p>}
      </div>
    </div>
  );
}
