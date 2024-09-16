# Stytch B2B DFP Adaptive MFA Example
This example app demonstrates how to leverage [Stytch's Device Fingerprinting (DFP)](https://stytch.com/docs/fraud/guides) product to power **Adaptive MFA**, where users are only required to complete MFA if they are logging in on a new device.

The app supports organization creation and demos limited management features.  After authentication, users have the ability to create new organizations.  Once created, authenticated users can manage the configuration of Just-in-Time (JIT) Provisioning, to tailor the onboarding process to their specific needs. JIT provisioning allows administrators to enable automatic user onboarding for specific email domains, such as new users with email addresses matching the specified domains.

It tracks the user's known devices in an in-memory dictionary after successful MFA and verdict from DFP and uses that information to determine if the subsequent login attempt should be challenged with MFA.

The following use cases in the app demonstrate the integration of [Stytch's B2B authentication](https://stytch.com/docs/b2b/overview), [MFA](https://stytch.com/docs/b2b/guides/mfa/overview), and [Device Fingerprinting](https://stytch.com/docs/fraud/guides) capabilities:

1. **New User Login and MFA Enrollment**:
   - A new user logs in for the first time.
   - They are prompted to enroll in MFA by providing a phone number.
   - After successful MFA enrollment, their device is marked as trusted.

2. **Returning User on Known Device**:
   - A returning user attempts to log in on a previously used device.
   - The app recognizes the device and allows login without MFA.

3. **Returning User on New Device**:
   - A returning user attempts to log in on a new, unrecognized device.
   - The app prompts for MFA verification before allowing login.
   - After successful MFA, the new device is marked as trusted for future logins.

4. **DFP Verdict Handling**:
   - The app checks the DFP verdict for each login attempt.
   - If the verdict is "BLOCK", the login is denied (simulated by redirecting to a success page to avoid revealing the block).
   - If the verdict is "CHALLENGE", MFA is required even for known devices.

## Get Started
In order to run this example app you need to have signed up for a Stytch account, and request access to our DFP product (a step we require for security purposes).

Ensure you have pip, python and virtualenv installed.

#### 1. Clone the repository.
```
git clone https://github.com/stytchauth/stytch-b2b-dfp-mfa-example.git
cd stytch-b2b-dfp-mfa-example
```

#### 2. Setup a virtualenv

We suggest creating a [virtualenv](https://docs.python.org/3/library/venv.html) and activating it to avoid installing dependencies globally
```
virtualenv -p python3 venv
source venv/bin/activate
```

#### 3. Install dependencies:
```
pip install -r requirements.txt
```

#### 4. Set ENV vars

Copy `.env.template` to `.env` and update the values with your Stytch project ID, secret and public token from [the API Keys section of the Stytch Dashboard](https://stytch.com/dashboard/api-keys).

#### 7. Run the Server
Run
```
python3 main.py
```
Go to http://localhost:3000/

## Adding Stytch DFP 'CHALLENGE' and 'BLOCK' authorization rules

Once you've set up your Stytch project and have your API keys and signed into the app, you can use the [Stytch Dashboard](https://stytch.com/dashboard/device-fingerprinting?tab=rules) to add 'CHALLENGE' and 'BLOCK' authorization rules to test the behavior of the app.

1. Go to [Device Fingerprinting in the Stytch Dashboard](https://stytch.com/dashboard/device-fingerprinting?tab=rules)
2. Click on 'New Rule'
3. Paste the fingerprint of the device you want to enforce a verdict of 'CHALLENGE' or 'BLOCK'
4. Choose 'CHALLENGE' or 'BLOCK' from the 'Action' dropdown
5. Click 'Save'
6. Attempt to login with the device that has the fingerprint you just added and observe the behavior of the app.

You can repeat this process for additional devices.


## Next steps

This example app showcases a small portion of what you can accomplish with Stytch. Next, explore adding additional login methods, such as [OAuth](https://stytch.com/docs/b2b/guides/oauth/initial-setup) or [SSO](https://stytch.com/docs/b2b/guides/sso/initial-setup).

## Get help and join the community

#### :speech_balloon: Stytch community Slack

Join the discussion, ask questions, and suggest new features in our ​[Slack community](https://stytch.com/docs/resources/support/overview)!

#### :question: Need support?

Check out the [Stytch Forum](https://forum.stytch.com/) or email us at [support@stytch.com](mailto:support@stytch.com).
