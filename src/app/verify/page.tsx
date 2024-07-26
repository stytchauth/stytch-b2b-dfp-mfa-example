"use client";

import { useStytchMember } from "@stytch/nextjs/b2b";
import { useSearchParams } from "next/navigation";
import VerifySMSMFA from "../../components/VerifySMSMFA";

export default function VerifyPage() {
  const query = useSearchParams();
  const member_id = query.get("member_id");
  const organization_id = query.get("organization_id");
  const { member } = useStytchMember();

  console.log("member", member);
  return (
    <VerifySMSMFA
      sendVerifyCode={true}
      member_id={member_id ?? member?.member_id ?? ""}
      organization_id={organization_id ?? member?.organization_id ?? ""}
    />
  );
}
