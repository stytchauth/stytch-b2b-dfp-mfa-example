import {
  useStytchMemberSession,
  useStytchOrganization,
} from "@stytch/nextjs/b2b";
import { redirect } from "next/navigation";
import { useMemo } from "react";
import "./Dashboard.css";

const Dashboard = () => {
  const { session } = useStytchMemberSession();
  const { organization } = useStytchOrganization();

  console.log("session", session);
  console.log("organization", organization);

  const role = useMemo(() => {
    return session?.roles.includes("stytch_admin") ? "admin" : "member";
  }, [session?.roles]);

  if (!session) {
    redirect("/");
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-content">
        Hello! You&apos;re logged into{" "}
        <strong>{organization?.organization_name}</strong> with{" "}
        <strong>{role}</strong> permissions.
      </div>
    </div>
  );
};

export default Dashboard;
