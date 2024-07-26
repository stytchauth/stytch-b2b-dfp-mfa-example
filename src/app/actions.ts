"use server";

const STYTCH_SECRET = process.env.STYTCH_SECRET;
const STYTCH_PROJECT_ID = process.env.STYTCH_PROJECT_ID;

export const stytchFingerprintLookup = async ({
  telemetry_id,
}: {
  telemetry_id: string;
}) => {
  try {
    const response = await fetch(
      `https://telemetry.stytch.com/v1/fingerprint/lookup?telemetry_id=${telemetry_id}`,
      {
        method: "GET",
        headers: {
          Authorization:
            "Basic " + btoa(`${STYTCH_PROJECT_ID}:${STYTCH_SECRET}`),
        },
      },
    );

    if (!response.ok) {
      throw new Error(`Error: ${response.statusText}`);
    }

    const data = await response.json();
    console.log("DFP Lookup:", data);
    return data;
  } catch (err: any) {
    console.error(err);
    throw new Error(err.message);
  }
};
