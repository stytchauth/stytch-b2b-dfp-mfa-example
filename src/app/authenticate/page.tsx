"use client";

import VerifySMSMFA from "@/src/components/VerifySMSMFA";
import { useStytchB2BClient, useStytchMember } from "@stytch/nextjs/b2b";
import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";
import EnrollMFA from "../../components/EnrollMFA";

export default function AuthenticatePage() {
  const { member } = useStytchMember();
  const stytch = useStytchB2BClient();
  const router = useRouter();

  const [error, setError] = useState<string | null>(null);
  const [phoneNumber, setPhoneNumber] = useState("");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [step, setStep] = useState("authenticate"); // 'authenticate', 'enroll', or 'verify'
  const [isLoading, setIsLoading] = useState(false);
  const [memberId, setMemberId] = useState<string | null>(null);
  const [organizationId, setOrganizationId] = useState<string | null>(null);

  useEffect(() => {
    const authenticateUser = async () => {
      const token = new URLSearchParams(window.location.search).get("token");
      const tokenType = new URLSearchParams(window.location.search).get(
        "stytch_token_type",
      );

      if (token && tokenType === "discovery") {
        try {
          const authenticateResponse =
            await stytch.magicLinks.discovery.authenticate({
              discovery_magic_links_token: token,
            });
          const {
            email_address,
            discovered_organizations,
            intermediate_session_token,
          } = authenticateResponse;
          console.log("authenticateResponse", authenticateResponse);

          let createdOrganization;
          let discoveredOrganization;
          if (discovered_organizations.length === 0) {
            console.log("No discovered organizations found");
            createdOrganization = await stytch.discovery.organizations.create({
              organization_name: `${email_address}'s Organization`,
              organization_slug: email_address.split("@")[0],
              session_duration_minutes: 60,
              mfa_policy: "REQUIRED_FOR_ALL",
            });
          } else {
            discoveredOrganization = discovered_organizations[0];
          }

          let exchangeResponse;
          try {
            exchangeResponse =
              await stytch.discovery.intermediateSessions.exchange({
                organization_id:
                  createdOrganization?.organization.organization_id ||
                  discoveredOrganization?.organization.organization_id ||
                  "",
                session_duration_minutes: 60,
              });
          } catch (error) {
            console.error("Error:", error);
            return;
          }

          if (
            exchangeResponse.member_authenticated === false &&
            exchangeResponse.mfa_required.member_options === null
          ) {
            setStep("enroll");
            setMemberId(exchangeResponse.member.member_id);
            setOrganizationId(exchangeResponse.member.organization_id);
          } else if (
            exchangeResponse.member_authenticated === false &&
            exchangeResponse.mfa_required?.member_options !== null
          ) {
            setStep("verify");
            setMemberId(exchangeResponse.member.member_id);
            setOrganizationId(exchangeResponse.member.organization_id);
          } else {
            router.push("/dashboard");
          }
        } catch (err) {
          router.push("/");
          console.error("Authentication error:", err);
          setError("Failed to authenticate. Please try again.");
        }
      }
    };

    authenticateUser();
  }, [router, stytch]);

  const handlePhoneNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPhoneNumber(e.target.value);
    setMessage("");
  };

  const sendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!memberId || !organizationId) {
      setMessage("Error: Member information is missing.");
      return;
    }
    setIsLoading(true);
    try {
      await stytch.otps.sms.send({
        member_id: memberId,
        organization_id: organizationId,
        mfa_phone_number: phoneNumber,
      });
      setStep("verify");
      setMessage("Code sent successfully. Please check your phone.");
    } catch (error) {
      console.error("Error sending code:", error);
      setMessage("Error sending code. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const renderError = () => <div className="error-message">{error}</div>;

  const renderAuthenticating = () => (
    <div className="authenticating">
      <p>Authenticating...</p>
      <p>Please wait while we process your request.</p>
    </div>
  );

  const renderEnroll = () => (
    <EnrollMFA
      phoneNumber={phoneNumber}
      isLoading={isLoading}
      message={message}
      onPhoneNumberChange={handlePhoneNumberChange}
      onSendCode={sendCode}
    />
  );

  const renderVerify = () => (
    <VerifySMSMFA
      member_id={memberId ?? ""}
      organization_id={organizationId ?? ""}
    />
  );

  if (error) return renderError();
  if (step === "authenticate") return renderAuthenticating();
  if (step === "enroll") return renderEnroll();
  if (step === "verify") return renderVerify();

  return null;
}
