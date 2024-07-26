"use client";

import { useStytchB2BClient } from "@stytch/nextjs/b2b";
import React, { useState } from "react";
import "./Login.css";

const Login = () => {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const stytch = useStytchB2BClient();

  const sendDiscoveryEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await stytch.magicLinks.email.discovery.send({
        email_address: email,
      });
      setMessage("Magic link sent! Check your email.");
    } catch (error) {
      console.error("Error sending magic link:", error);
      setMessage("Error sending magic link. Please try again.");
    }
  };

  return (
    <div className="login-container">
      <div className="login-content">
        <h2 className="login-title">Sign in to your account</h2>

        <form onSubmit={sendDiscoveryEmail} className="login-form">
          <div className="form-group">
            <label htmlFor="email">Email address</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>

          <button type="submit" className="submit-button">
            Send Magic Link
          </button>
        </form>

        {message && <p className="message">{message}</p>}
      </div>
    </div>
  );
};

export default Login;
