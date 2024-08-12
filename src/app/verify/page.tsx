"use client";

import { useStytchMember } from "@stytch/nextjs/b2b";
import VerifySMSMFA from "../../components/VerifySMSMFA";

export default function VerifyPage() {
  const { member } = useStytchMember();

  console.log("member", member);
  return (
    <VerifySMSMFA
      sendVerifyCode={true}
      member_id={member?.member_id ?? ""}
      organization_id={member?.organization_id ?? ""}
    />
  );
}
