import axios from "axios";
import dotenv from "dotenv";

dotenv.config({ path: ".env.local" });

const PROJECT_ID = process.env.STYTCH_PROJECT_ID;
const SECRET = process.env.STYTCH_SECRET;

if (!PROJECT_ID || !SECRET) {
  console.error(
    "Error: STYTCH_PROJECT_ID and STYTCH_SECRET must be set in your .env file",
  );
  process.exit(1);
}

const setRule = async (visitorId, action) => {
  try {
    const response = await axios.post(
      "https://telemetry.stytch.com/v1/rules/set",
      {
        visitor_id: visitorId,
        action: action,
      },
      {
        auth: {
          username: PROJECT_ID,
          password: SECRET,
        },
      },
    );
    console.log("Rule set successfully:", response.data);
  } catch (error) {
    console.error(
      "Error setting rule:",
      error.response ? error.response.data : error.message,
    );
  }
};

const main = () => {
  const visitorId = process.argv[2];
  const action = process.argv[3];

  if (!visitorId || !action) {
    console.log(
      "Usage: node changeVerdict.js <visitor_id> <ALLOW|BLOCK|CHALLENGE>",
    );
    process.exit(1);
  }

  if (!["ALLOW", "BLOCK", "CHALLENGE"].includes(action.toUpperCase())) {
    console.log("Error: Action must be one of ALLOW, BLOCK, or CHALLENGE");
    process.exit(1);
  }

  setRule(visitorId, action.toUpperCase());
};

main();
