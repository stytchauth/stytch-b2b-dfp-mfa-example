import * as stytch from "stytch";

let client: stytch.B2BClient;

/*
loadStytch initializes the Stytch Backend SDK using your project's id and secret. The Backend SDK can be used 
on any code paths that run server side.
*/
const loadStytch = () => {
  if (!client) {
    client = new stytch.B2BClient({
      project_id: process.env.STYTCH_PROJECT_ID || "",
      secret: process.env.STYTCH_SECRET || "",
      env:
        process.env.STYTCH_PROJECT_ENV === "live"
          ? stytch.envs.live
          : stytch.envs.test,
    });
  }

  return client;
};

export default loadStytch;
