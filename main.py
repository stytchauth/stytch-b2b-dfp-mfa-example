import os
import sys

import logging
from pprint import pformat
import dotenv
import requests
import stytch
from stytch.b2b.models.organizations import UpdateRequestOptions
from stytch.shared.method_options import Authorization
from flask import Flask, request, url_for, session, redirect, render_template
from stytch.core.response_base import StytchError

# load the .env file
dotenv.load_dotenv()

# By default, run on localhost:3000
HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", "3000"))

# Set ENV to "live" to hit the live API environment
ENV = os.getenv("ENV", "test")

# Load the Stytch credentials, but quit if they aren't defined
STYTCH_PROJECT_ID = os.getenv("STYTCH_PROJECT_ID")
if STYTCH_PROJECT_ID is None:
    sys.exit("STYTCH_PROJECT_ID env variable must be set before running")

STYTCH_SECRET = os.getenv("STYTCH_SECRET")
if STYTCH_SECRET is None:
    sys.exit("STYTCH_SECRET env variable must be set before running")

STYTCH_PUBLIC_TOKEN = os.getenv("STYTCH_PUBLIC_TOKEN")
if STYTCH_PUBLIC_TOKEN is None:
    sys.exit("STYTCH_PUBLIC_TOKEN env variable must be set before running")

stytch_client = stytch.B2BClient(
    project_id=STYTCH_PROJECT_ID, secret=STYTCH_SECRET, environment=ENV
)

# create a Flask web app
app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app.secret_key = "some-secret-key"

# In-memory array to store known devices
# MemberID is key, value is array of VisitorFingerprints
known_devices = {}


@app.route("/")
def index():
    member, organization = get_authenticated_member_and_organization()
    if member and organization:
        logger.info("Active Session Found")
        logger.info(
            f"Session Member -- {member.email_address} | {member.member_id} \nSession Org -- {organization.organization_name} | {organization.organization_id}"
        )
        logger.info(f"Known Devices: {known_devices}")
        return render_template(
            "loggedIn.html",
            member=member,
            organization=organization,
            known_devices=known_devices,
        )

    logger.info("No active session -- prompting to login")
    return render_template("discoveryLogin.html", public_token=STYTCH_PUBLIC_TOKEN)


@app.route("/logout")
def logout():
    session.pop("stytch_session_token", None)
    return redirect(url_for("index"))


# Example of initiating discovery magic link authentication
# from a central login page and protecting this flow from attackers
# by using Stytch's Device Fingerprinting product
@app.route("/send_magic_link", methods=["POST"])
def send_eml():

    data = request.get_json()
    email = data.get("email", None)
    if email is None:
        logger.error("Email not included")
        return redirect(url_for("oops"))

    # Use DFP lookup response to proactively block fraudulent traffic from attempting to login
    telemetry_id = request.headers.get("X-Telemetry-ID", "")
    data = fingerprint_lookup(telemetry_id)
    if data is None:
        logger.error("DFP Lookup of TelemetryID failed.")
        return redirect(url_for("oops"))

    verdict_action = data.get("verdict", {}).get("action", "")
    if verdict_action == "BLOCK":
        logger.info(
            "DFP Verdict Action is BLOCK -- returning success page to obfuscate fingerprint block"
        )
        return redirect(url_for("email_sent"))
    if verdict_action == "CHALLENGE":
        logger.info(
            "DFP Verdict Action is CHALLENGE -- will require step-up MFA even if known device"
        )

    try:
        stytch_client.magic_links.email.discovery.send(email_address=email)
    except StytchError as e:
        logger.error(f"Error sending discovery magic link: {e.details}")
        return redirect(url_for("oops"))

    return redirect(url_for("email_sent"))


# Your default Redirect URL for discovery login
# This Redirect URL is automatically called by Stytch when the user clicks on the magic link to authenticate
# and allows you to securely exchange the authentication token for an intermediate_session_token
# and information about the Organizations the user can log into
# Read more about Redirect URLs and Token Types here: https://stytch.com/docs/b2b/guides/dashboard/redirect-urls
@app.route("/authenticate", methods=["GET"])
def authenticate():
    token_type = request.args["stytch_token_type"]
    token = request.args["token"]

    if token_type != "discovery":
        logger.error("Unsupported token type")
        return redirect(url_for("oops"))
    try:
        resp = stytch_client.magic_links.discovery.authenticate(
            discovery_magic_links_token=token
        )
    except StytchError as e:
        logger.error(f"Error authenticating magic link token: {e.details}")
        return redirect(url_for("oops"))

    # The intermediate_session_token (IST) allows you to persist authentication state
    # while you present the user with the Organizations they can log into, or the option to create a new Organization
    session["ist"] = resp.intermediate_session_token
    orgs = []
    for discovered in resp.discovered_organizations:
        org = {
            "organization_id": discovered.organization.organization_id,
            "organization_name": discovered.organization.organization_name,
        }
        orgs.append(org)

    return render_template(
        "discoveredOrganizations.html",
        discovered_organizations=orgs,
        email_address=resp.email_address,
        is_login=True,
        public_token=STYTCH_PUBLIC_TOKEN,
    )


# Example of creating a new Organization after Discovery authentication
# To test, select "Create New Organization" and input a name and slug for your new org
# This will then exchange the IST returned from the discovery.authenticate() call
# which allows Stytch to enforce that users are properly authenticated and verified
# prior to creating an Organization
@app.route("/create_organization", methods=["POST"])
def create_organization():
    ist = session.get("ist")
    if not ist:
        logger.error("IST required to create an Organization")
        return redirect(url_for("oops"))

    org_name = request.form.get("org_name", "")
    org_slug = request.form.get("org_slug", "")
    clean_org_slug = org_slug.replace(" ", "-")

    try:
        resp = stytch_client.discovery.organizations.create(
            intermediate_session_token=ist,
            organization_name=org_name,
            organization_slug=clean_org_slug,
        )
    except StytchError as e:
        logger.error(f"Error creating organization: {e.details}")
        return redirect(url_for("oops"))

    # New Organizations have an OPTIONAL MFA Policy by default
    # Set the Member's session in cookies and prompt them to enroll in MFA
    session.pop("ist")
    session["stytch_session_token"] = resp.session_token
    return redirect(url_for("enroll_mfa_prompt"))


# During the Discovery flow users can opt to log into an existing Organization that
# they are an active member of, have a pending invite, or are eligible to join based
# on their verified email domain
# You will exchange the IST returned from the discovery.authenticate() method call
# to complete the login process
@app.route("/exchange/<string:organization_id>", methods=["POST"])
def exchange_into_organization(organization_id):

    discovered_organization = get_discovered_organization(organization_id)
    if discovered_organization is None:
        logger.info(
            "Discovered organization not found, unable to exchange into Organization"
        )
        return redirect(url_for("oops"))

    member = discovered_organization.membership.member

    if (
        not discovered_organization.member_authenticated
        and discovered_organization.mfa_required
    ):
        logger.info(
            "Organization MFA Policy is REQUIRED_FOR_ALL. User is required to complete MFA regardless of device."
        )
        return redirect(url_for("mfa_otp_prompt", organization_id=organization_id))

    # Handle case where user is JIT Provisioning into an Organization with an OPTIONAL MFA policy
    # Prompt to enroll in adaptive MFA
    if discovered_organization.membership.type == "eligible_to_join_by_email_domain":
        logger.info(
            f"JIT Provisioning into OrgID: {discovered_organization.organization.organization_id}"
        )
        ist = session.get("ist", None)
        try:
            stytch_client.discovery.intermediate_sessions.exchange(
                organization_id=organization_id,
                intermediate_session_token=ist,
            )
        except StytchError as e:
            logger.error(
                f"Unable to exchange IST for Org Session when JIT Provisioning: {e.details}"
            )
            return redirect(url_for("oops"))

        return redirect(url_for("enroll_mfa_prompt"))

    if not member.mfa_phone_number:
        logger.info(
            "MFA not required for Organization and Member has not opted into adaptive MFA. Logging in."
        )
        return exchange_ist_for_org_session(organization_id)

    # Handle case where member is enrolled in adaptive MFA
    # First check to see if current device is a known device for the member
    telemetry_id = request.headers.get("X-Telemetry-ID", "")
    data = fingerprint_lookup(telemetry_id)
    if data:
        verdict_action = data.get("verdict", {}).get("action", "")
        visitor_fingerprint = data.get("fingerprints", {}).get(
            "visitor_fingerprint", None
        )
        known_devices_for_member = known_devices.get(member.member_id, set())

        is_known_device = visitor_fingerprint in known_devices_for_member
        # logger.info(
        #     f"VisitorFingerprint: {visitor_fingerprint} | Is Known: {is_known_device} | Verdict Action: {verdict_action}"
        # )

        if is_known_device and verdict_action == "ALLOW":
            logger.info(
                "Known authentic device. Skipping MFA and exchanging IST for Session."
            )
            return exchange_ist_for_org_session(organization_id)
    else:
        logger.info(
            "Error looking up TelemetryID. Triggering MFA since unable to verify if known device"
        )

    logger.info(
        "Unknown or untrusted device for member enrolled in adaptive MFA. Triggering MFA."
    )
    ist = session.get("ist")
    if ist is None:
        logger.warning("IST or Session Token required to trigger adaptive MFA")
        return redirect(url_for("oops"))

    try:
        stytch_client.otps.sms.send(
            organization_id=organization_id,
            member_id=member.member_id,
            intermediate_session_token=ist,
        )
    except StytchError as e:
        logger.error(f"Unable to trigger OTPS SMS Send with IST: {e.details}")
        return redirect(url_for("oops"))

    return redirect(url_for("mfa_otp_prompt", organization_id=organization_id))


# Renders template for the user to input the OTP they were sent via SMS
# Used for returning users who have already registered an MFA phone
@app.route("/mfa-otp-prompt/<string:organization_id>", methods=["GET"])
def mfa_otp_prompt(organization_id):

    discovered_organization = get_discovered_organization(organization_id)
    if discovered_organization is None:
        logger.info("Discovered Organization not found when prompting for MFA OTP.")
        return redirect(url_for("oops"))

    return render_template(
        "inputMFACode.html",
        public_token=STYTCH_PUBLIC_TOKEN,
        organization_id=organization_id,
        member_id=discovered_organization.membership.member.member_id,
    )


# Triggers the initial SMS send to enroll a member in MFA
# and renders template for the user to input the OTP they were sent via SMS
@app.route("/start-mfa-enrollment", methods=["POST"])
def start_mfa_enrollment():
    country_code = request.form.get("country_code")
    phone = request.form.get("phone")
    phone_number = f"{country_code}{phone}"
    if not phone:
        logger.error("Phone not provided")
        return redirect(url_for("oops"))

    member, organization = get_authenticated_member_and_organization()
    if member is None or organization is None:
        return redirect(url_for("index"))
    try:
        stytch_client.otps.sms.send(
            organization_id=organization.organization_id,
            member_id=member.member_id,
            mfa_phone_number=phone_number,
        )
    except StytchError as e:
        logger.error(f"Error sending OTP for MFA enrollment: {e.details}")
        return redirect(url_for("oops"))

    logger.info("SMS send successful, prompting user for OTP to complete enrollment")
    return render_template(
        "inputMFACode.html",
        public_token=STYTCH_PUBLIC_TOKEN,
        organization_id=organization.organization_id,
        member_id=member.member_id,
    )


# Authenticates the MFA code (OTP) sent via SMS
# If verified, will mint a session for the Member and store the current
# VisitorFingerprint in the list of KnownDevices for the MemberID
@app.route("/authenticate-mfa-code", methods=["POST"])
def authenticate_mfa_code() -> str:

    data = request.get_json()
    code = data.get("code", None)
    organization_id = data.get("organization_id")

    ist = session.get("ist", None)
    session_token = session.get("stytch_session_token", None)
    if ist is None and session_token is None:
        logger.error("IST or Session Token required to complete MFA authentication")
        return redirect(url_for("oops"))

    if ist:
        logger.info("Performing MFA authentication for login")
        discovered_organization = get_discovered_organization(organization_id)
        if discovered_organization is None:
            logger.info(
                "Discovered organization not found from IST during MFA authentication"
            )
            return redirect(url_for("oops"))

        member_id = discovered_organization.membership.member.member_id

        try:
            resp = stytch_client.otps.sms.authenticate(
                code=code,
                organization_id=organization_id,
                member_id=discovered_organization.membership.member.member_id,
                intermediate_session_token=ist,
            )
        except StytchError as e:
            logger.error(
                f"Error authenticating OTP during MFA authentication with IST: {e.details}"
            )
            return redirect(url_for("oops"))

        session.pop("ist")
        session["stytch_session_token"] = resp.session_token

    else:
        logger.info("Performing MFA authentication for enrollment")
        member, organization = get_authenticated_member_and_organization()
        if member is None:
            logger.error(
                "Member not found via session for MFA authentication enrollment"
            )
            return redirect(url_for("oops"))

        try:
            resp = stytch_client.otps.sms.authenticate(
                code=code,
                organization_id=organization_id,
                member_id=member.member_id,
                session_token=session_token,
            )
        except StytchError as e:
            logger.error(
                f"Error authenticating OTP during MFA authentication with session token: {e.details}"
            )
            return redirect(url_for("oops"))

        session["stytch_session_token"] = resp.session_token

    # Lookup the VisitorFingerprint and add to known devices for MemberID
    telemetry_id = request.headers.get("X-Telemetry-ID", "")
    data = fingerprint_lookup(telemetry_id)
    if data is None:
        logger.info(
            "Lookup of TelemetryID failed, unable to add device to known devices"
        )
        return redirect(url_for("index"))

    visitor_fingerprint = data.get("fingerprints", {}).get("visitor_fingerprint", None)
    known_devices.setdefault(member_id, set()).add(visitor_fingerprint)

    return redirect(url_for("index"))


# Example of authorized updating of Organization Settings + Just-in-Time (JIT) Provisioning
# Once enabled:
# 1. Logout
# 2. Initiate magic link for an email alias (e.g. ada+1@stytch.com)
# 3. After clicking the Magic Link you'll see the option to join the organization with JIT enabled
# Use your work email address to test this, as JIT cannot be enabled for common email domains
@app.route("/enable_jit")
def enable_jit():
    member, organization = get_authenticated_member_and_organization()
    if member is None or organization is None:
        return redirect(url_for("index"))

    # Note: not allowed for common domains like gmail.com
    domain = member.email_address.split("@")[1]

    # When the session_token or session_jwt are passed into method_options
    # Stytch will do AuthZ enforcement based on the Session Member's RBAC permissions
    # before honoring the request
    try:
        stytch_client.organizations.update(
            organization_id=organization.organization_id,
            email_jit_provisioning="RESTRICTED",
            email_allowed_domains=[domain],
            method_options=UpdateRequestOptions(
                authorization=Authorization(
                    session_token=session.get("stytch_session_token", None),
                ),
            ),
        )
    except StytchError as e:
        logger.error(
            f"Error updating Organization JIT Provisioning settings: {e.details}"
        )
        return redirect(url_for("oops"))

    return redirect(url_for("index"))


@app.route("/email_sent")
def email_sent():
    return render_template("emailSent.html")


@app.route("/oops")
def oops():
    return render_template("oops.html")


@app.route("/enroll-mfa-prompt", methods=["GET"])
def enroll_mfa_prompt():
    return render_template("enrollMFA.html", public_token=STYTCH_PUBLIC_TOKEN)


# Helper function to get the DiscoveredOrganizations object for a specified
# OrganizationID using the user's current IST
def get_discovered_organization(organization_id):
    ist = session.get("ist", None)
    if ist is None:
        logger.warning("IST not found, unable to fetch discovered organization")
        return None
    try:
        resp = stytch_client.discovery.organizations.list(
            intermediate_session_token=ist
        )
    except StytchError as e:
        logger.error(f"Error fetching discovered organizations by IST: {e.details}")
        return None

    for discovered_org in resp.discovered_organizations:
        if discovered_org.organization.organization_id == organization_id:
            return discovered_org

    # OrgID passed not found in discovered organizations for IST
    return None


# Helper to retrieve the authenticated Member and Organization context
def get_authenticated_member_and_organization():
    stytch_session = session.get("stytch_session_token")
    if not stytch_session:
        return None, None

    try:
        resp = stytch_client.sessions.authenticate(session_token=stytch_session)
        # Remember to reset the cookie session, as sessions.authenticate() will issue a new token
        session["stytch_session_token"] = resp.session_token
        return resp.member, resp.organization
    except StytchError as e:
        if e.details.error_type == "session_not_found":
            # Session has expired or is invalid, clear it
            session.pop("stytch_session_token", None)
        logger.warning(f"Session authentication failed: {e}")
        return None, None


# Helper to get the lookup data for a given TelemetryID
def fingerprint_lookup(telemetry_id: str):
    lookup_url = f"https://telemetry.stytch.com/v1/fingerprint/lookup?telemetry_id={telemetry_id}"
    auth = (STYTCH_PROJECT_ID, STYTCH_SECRET)

    resp = requests.get(lookup_url, auth=auth)
    if resp.status_code != 200:
        error_message = str(resp.json()).replace("\r\n", "").replace("\n", "")
        logger.error(f"Error looking up TelemetryID: {error_message}")
        return None

    return resp.json()


# Helper for exchanging the Intermediate Session Token (IST)
# for a Member Session on the specified Organization
def exchange_ist_for_org_session(organization_id):
    ist = session.get("ist", None)
    if ist is None:
        logger.error("IST not found to exchange for org session token")
        return redirect(url_for("oops"))

    # Exchange IST for stytch_session_token in selected organization
    try:
        resp = stytch_client.discovery.intermediate_sessions.exchange(
            organization_id=organization_id,
            intermediate_session_token=ist,
        )
    except StytchError as e:
        logger.error(f"Unable to exchange IST for org session: {e.details}")
        return redirect(url_for("oops"))

    # Set new stytch_session_token and discard IST if relevant
    session.pop("ist")
    session["stytch_session_token"] = resp.session_token
    return redirect(url_for("index"))


# run's the app on the provided host & port
if __name__ == "__main__":
    # in production you would want to make sure to disable debugging
    app.run(host=HOST, port=PORT, debug=True)
