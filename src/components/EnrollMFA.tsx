import React from "react";
import "./VerifySMSMFA.css";

interface EnrollMFAProps {
  phoneNumber: string;
  isLoading: boolean;
  message: string;
  onPhoneNumberChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onSendCode: (e: React.FormEvent) => void;
}

export default function EnrollMFA({
  phoneNumber,
  isLoading,
  message,
  onPhoneNumberChange,
  onSendCode,
}: EnrollMFAProps) {
  return (
    <div className="login-container">
      <div className="login-content">
        <h2 className="login-title">Enroll in MFA</h2>
        <form onSubmit={onSendCode} className="login-form">
          <div className="form-group">
            <label htmlFor="phone-number">
              Enter your phone number to set up Multi-Factor Authentication
            </label>
            <input
              id="phone-number"
              type="tel"
              pattern="+[0-9]*"
              value={phoneNumber}
              onChange={onPhoneNumberChange}
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
