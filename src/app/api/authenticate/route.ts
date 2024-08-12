import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { NextRequest, NextResponse } from "next/server";
import loadStytch from "../../loadStytch";

export async function GET(request: NextRequest) {
  const stytch = loadStytch();
  const searchParams = request.nextUrl.searchParams;
  const token = searchParams.get("token");
  const stytch_token_type = searchParams.get("stytch_token_type");

  if (!token || stytch_token_type !== "discovery") {
    return NextResponse.json({ error: "Invalid token" }, { status: 400 });
  }

  let authenticateResponse;
  try {
    authenticateResponse = await stytch.magicLinks.discovery.authenticate({
      discovery_magic_links_token: token,
    });

    console.log(authenticateResponse);
  } catch (err) {
    console.error("Authentication error:", err);
    return NextResponse.json(
      { error: "Authentication failed" },
      { status: 500 },
    );
  }

  const { email_address, discovered_organizations } = authenticateResponse;

  let createdOrganization;
  let organizationId;
  if (discovered_organizations.length === 0) {
    try {
      createdOrganization = await stytch.discovery.organizations.create({
        organization_name: `${email_address}'s Organization`,
        organization_slug: email_address.split("@")[0],
        session_duration_minutes: 60,
        intermediate_session_token:
          authenticateResponse.intermediate_session_token,
      });
      console.log("Created organization", createdOrganization);
      organizationId = createdOrganization.organization?.organization_id;
    } catch (err) {
      console.error("Organization creation error:", err);
      return NextResponse.json(
        { error: "Organization creation failed" },
        { status: 500 },
      );
    }
  } else {
    organizationId = discovered_organizations[0].organization?.organization_id;
  }

  if (createdOrganization?.member_authenticated) {
    cookies().set("stytch_session", createdOrganization.session_token);
    cookies().set("stytch_session_jwt", createdOrganization.session_jwt);
    // Created Org - redirecting to Enroll MFA
    console.log("Created Org - redirecting to Enroll MFA");
    redirect("/enroll-mfa");
  }

  let exchangeResponse;
  try {
    exchangeResponse = await stytch.discovery.intermediateSessions.exchange({
      organization_id: organizationId ?? "",
      intermediate_session_token:
        authenticateResponse.intermediate_session_token,
    });

    console.log("exchangeResponse", exchangeResponse);
  } catch (err) {
    console.error("Exchange error:", err);
    return NextResponse.json({ error: "Exchange failed" }, { status: 500 });
  }

  cookies().set("stytch_session", exchangeResponse.session_token);
  cookies().set("stytch_session_jwt", exchangeResponse.session_jwt);

  if (exchangeResponse.member_authenticated === false) {
    if (exchangeResponse.mfa_required?.member_options === null) {
      // Enroll MFA
      console.log("Enroll MFA");
      redirect("/enroll_mfa");
    } else {
      // Verify MFA
      console.log("Verify MFA");
      redirect("/verify_mfa");
    }
  } else {
    // Authenticated
    console.log("Authenticated");
    redirect("/dashboard");
  }
}
