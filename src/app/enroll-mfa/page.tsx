"use client";

import { useStytchMember } from "@stytch/nextjs/b2b";
import EnrollMFA from "../../components/EnrollMFA";

export default function EnrollMFAPage() {
  const { member } = useStytchMember();

  console.log("enroll mfa member", member);
  return (
    <EnrollMFA
      memberId={member?.member_id ?? ""}
      organizationId={member?.organization_id ?? ""}
    />
  );
}
