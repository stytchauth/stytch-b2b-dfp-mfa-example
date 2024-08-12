"use server";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import loadStytch from "./loadStytch";

const STYTCH_SECRET = process.env.STYTCH_SECRET;
const STYTCH_PROJECT_ID = process.env.STYTCH_PROJECT_ID;

const knownDevices: string[] = [];
// Devices received a CHALLENGE verdict on their initial validation session
const knownDevicesInitialChallenge: string[] = [];

export const addKnownDeviceAfterVerify = () => {
  const device = cookies().get("vf");

  if (device) {
    // Add the known device to knownDevices
    knownDevices.push(device.value);
    // Delete the temporary cookie
    cookies().delete("vf");
    console.log("Known device added", knownDevices);
  }
};

const getStytchSession = () => {
  return cookies().get("stytch_session")?.value;
};

export const stytchFingerprintLookupAndRedirect = async ({
  telemetry_id,
  route,
}: {
  telemetry_id: string;
  route: string;
}) => {
  let response;
  try {
    response = await fetch(
      `https://telemetry.stytch.com/v1/fingerprint/lookup?telemetry_id=${telemetry_id}`,
      {
        method: "GET",
        headers: {
          Authorization:
            "Basic " + btoa(`${STYTCH_PROJECT_ID}:${STYTCH_SECRET}`),
        },
      },
    );
  } catch (err: any) {
    console.error(err);
    throw new Error(err.message);
  }

  const data = await response.json();

  const { verdict, fingerprints } = data;

  // Check if the device is known
  const isKnownDevice = knownDevices.includes(fingerprints.visitor_fingerprint);

  // If the device is known, redirect to the route
  if (isKnownDevice) {
    console.log("Known device");
    redirect(route);
  }

  // If the device is not known, check the verdict
  if (verdict?.action === "ALLOW") {
    // Set a temporary cookie to store the device fingerprint
    cookies().set("vf", fingerprints.visitor_fingerprint);
    redirect(route);
  } else if (verdict?.action === "BLOCK") {
    // If the verdict is BLOCK, redirect to the oops page
    redirect("/oops");
  } else if (verdict?.action === "CHALLENGE") {
    // If the verdict is CHALLENGE
    // Remove the known device from knownDevices
    knownDevices.splice(
      knownDevices.indexOf(fingerprints.visitor_fingerprint),
      1,
    );

    // Add the known device to knownDevicesInitialChallenge list
    knownDevicesInitialChallenge.push(fingerprints.visitor_fingerprint);

    // Redirect to the verify page
    redirect("/verify");
  } else {
    // otherwise redirect to the home page
    redirect(`/`);
  }
};

export const sendSMSCode = async (
  member_id: string,
  organization_id: string,
  mfa_phone_number?: string,
) => {
  const stytch = loadStytch();
  try {
    const response = await stytch.otps.sms.send({
      member_id,
      organization_id,
      mfa_phone_number,
    });
    return response;
  } catch (error) {
    console.error("Error sending SMS code:", error);
    throw error;
  }
};

export const verifySMSCode = async (
  member_id: string,
  organization_id: string,
  code: string,
) => {
  const stytch = loadStytch();
  console.log("verifySMSCode", member_id, organization_id, code);
  try {
    const result = await stytch.otps.sms.authenticate({
      member_id,
      organization_id,
      code,
      session_token: getStytchSession(),
      session_duration_minutes: 60,
    });

    return result;
  } catch (error) {
    console.error("Error authenticating MFA:", error);
    throw error;
  }
};
