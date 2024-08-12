import { stytchFingerprintLookupAndRedirect } from "./actions";

const public_token = process.env.NEXT_PUBLIC_STYTCH_PUBLIC_TOKEN;

const checkFingerprintAndRedirect = async (router: any, route: string) => {
  // @ts-ignore
  const telemetry_id = await GetTelemetryID(public_token);
  console.log("TID:", telemetry_id);

  await stytchFingerprintLookupAndRedirect({ telemetry_id, route });
};

export { checkFingerprintAndRedirect };
