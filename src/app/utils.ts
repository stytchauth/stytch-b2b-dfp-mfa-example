import { stytchFingerprintLookup } from "./actions";

const public_token = process.env.NEXT_PUBLIC_STYTCH_PUBLIC_TOKEN;

const checkFingerprintAndRedirect = async (router: any, route: string) => {
  // @ts-ignore
  const telemetry_id = await GetTelemetryID(public_token);

  const { verdict } = await stytchFingerprintLookup({ telemetry_id });
  console.log("V:", verdict);

  if (verdict?.action === "ALLOW") {
    router.push(route);
  } else if (verdict?.action === "BLOCK") {
    router.push("/blocked");
  } else if (verdict?.action === "CHALLENGE") {
    router.push("/verify");
  } else {
    router.push(`/`);
  }
};

export { checkFingerprintAndRedirect };
