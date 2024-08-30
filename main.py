import os
import sys

import logging
from pprint import pformat
import dotenv
import requests
import stytch
from stytch.b2b.models.organizations import SearchQuery
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
known_devices = []


@app.route("/")
def index():
    member, organization = get_authenticated_member_and_organization()
    logger.info("index - Member %s", member)
    logger.info("index - Organization %s", organization)
    if member and organization:
        return render_template(
            "loggedIn.html", member=member, organization=organization
        )

    return render_template("index.html", public_token=STYTCH_PUBLIC_TOKEN)


# Login route
@app.route("/login", methods=["GET"])
def login() -> str:
    telemetry_id = request.args.get("telemetry_id")
    logger.info("telemetry_id %s", telemetry_id)
    if telemetry_id:
        lookup_result = fingerprint_lookup(telemetry_id)
        verdict_action = lookup_result["verdict"]["action"]
        logger.info("VA %s", verdict_action)
        if verdict_action == "ALLOW":
            return render_template("discoveryLogin.html")
        elif verdict_action == "CHALLENGE":
            # Challenge via reCAPTCHA, etc
            return "Challenge"
        elif verdict_action == "BLOCK":
            return render_template("oops.html")
        else:
            return "Unsupported verdict action"
    else:
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("stytch_session_token", None)
    return redirect(url_for("index"))


# Example of initiating Magic Link authentication
# Magic Links can be used for "Discovery Sign-up or Login" (no OrgID passed)
# OR "Organization Login" (with an OrgID passed)
# You can read more about these differences here: https://stytch.com/docs/b2b/guides/login-flows
@app.route("/send_magic_link", methods=["POST"])
def send_eml():
    email = request.form.get("email", None)
    if email is None:
        return "Email is required", 400

    organization_id = request.form.get("organization_id", None)
    if organization_id is None:
        resp = stytch_client.magic_links.email.discovery.send(email_address=email)
        if resp.status_code != 200:
            print(resp)
            return "Error sending discovery magic link!", 500
        return render_template("emailSent.html")

    resp = stytch_client.magic_links.email.login_or_signup(
        email_address=email, organization_id=organization_id
    )
    if resp.status_code != 200:
        print(resp)
        return "Error sending organization magic link!", 500
    return render_template("emailSent.html")


# Example of completing multi-step auth flow
# For these flows Stytch will call the Redirect URL specified in your dashboard
# with an auth token and stytch_token_type that allow you to complete the flow
# Read more about Redirect URLs and Token Types here: https://stytch.com/docs/b2b/guides/dashboard/redirect-urls
@app.route("/authenticate", methods=["GET"])
def authenticate():
    token_type = request.args["stytch_token_type"]
    token = request.args["token"]

    if token_type == "discovery":
        resp = stytch_client.magic_links.discovery.authenticate(
            discovery_magic_links_token=token
        )
        if resp.status_code != 200:
            print(resp)
            return "Error authenticating discovery magic link", 500

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

    elif token_type == "multi_tenant_magic_links":
        resp = stytch_client.magic_links.authenticate(magic_links_token=token)
        if resp.status_code != 200:
            print(resp)
            return "Error authenticating organization magic link", 500

        session["stytch_session_token"] = resp.session_token

        return redirect(url_for("index"))
    else:
        return "Unsupported auth method", 500


# Example of creating a new Organization after Discovery authentication
# To test, select "Create New Organization" and input a name and slug for your new org
# This will then exchange the IST returned from the discovery.authenticate() call
# which allows Stytch to enforce that users are properly authenticated and verified
# prior to creating an Organization
@app.route("/create_organization", methods=["POST"])
def create_organization():
    ist = session.get("ist")
    if not ist:
        return "IST required to create an Organization", 400

    org_name = request.form.get("org_name", "")
    org_slug = request.form.get("org_slug", "")
    clean_org_slug = org_slug.replace(" ", "-")

    resp = stytch_client.discovery.organizations.create(
        intermediate_session_token=ist,
        organization_name=org_name,
        organization_slug=clean_org_slug,
    )
    if resp.status_code != 200:
        return "Error creating org"

    session.pop("ist", None)
    session["stytch_session_token"] = resp.session_token

    # After creating the organization, check if MFA enrollment is needed
    member, organization = get_authenticated_member_and_organization()
    if member and not member.mfa_enrolled:
        return redirect(url_for("enroll_mfa"))

    return redirect(url_for("index"))


# After Discovery, users can opt to log into an existing Organization
# that they belong to or are eligible to join by Email Domain JIT Provision or a pending invite
# You will exchange the IST returned from the discovery.authenticate() method call
# to complete the login process
@app.route("/exchange/<string:organization_id>")
def exchange_into_organization(organization_id):
    ist = session.get("ist", None)
    telemetry_id = request.args.get("telemetry_id")

    if ist:
        organization = get_organization_from_ist(organization_id)
        if not organization:
            return "Organization not found", 404

        member = organization.membership.member
        print("Member", member)

        if not organization.member_authenticated:
            if member.mfa_phone_number:
                if telemetry_id:
                    lookup_result = fingerprint_lookup(telemetry_id)
                    visitor_fingerprint = lookup_result["fingerprints"][
                        "visitor_fingerprint"
                    ]
                    verdict_action = lookup_result["verdict"]["action"]
                    logger.info("VF %s", visitor_fingerprint)
                    if verdict_action == "ALLOW":
                        if visitor_fingerprint not in known_devices:
                            logger.info("Device not known, sending MFA code")
                            resp = stytch_client.otps.sms.send(
                                organization_id=organization_id,
                                member_id=member.member_id,
                                mfa_phone_number=member.mfa_phone_number,
                            )

                            if resp.status_code != 200:
                                print(resp)
                                return "Error sending MFA code", 500

                            return redirect(
                                url_for(
                                    "verify_mfa",
                                    organization_id=organization_id,
                                    visitor_fingerprint=visitor_fingerprint,
                                )
                            )
                        else:
                            logger.info("Device already known")
                            logger.info("Exchanging IST into Organization")

                            resp = (
                                stytch_client.discovery.intermediate_sessions.exchange(
                                    organization_id=organization_id,
                                    intermediate_session_token=ist,
                                )
                            )

                            logger.info("IST Exchange Response: %s", resp)

                            if resp.status_code != 200:
                                print(resp)
                                return "Error exchanging IST into Organization", 500

                            session.pop("ist", None)
                            session["stytch_session_token"] = resp.session_token
                            return redirect(url_for("index"))
            else:
                print("No MFA phone number")
                return redirect(url_for("enroll_mfa"))

    session_token = session.get("stytch_session_token")
    if not session_token:
        return "Either IST or Session Token required", 400

    resp = stytch_client.sessions.exchange(
        organization_id=organization_id, session_token=session_token
    )
    if resp.status_code != 200:
        return "Error exchanging Session Token into Organization", 500
    session["stytch_session_token"] = resp.session_token
    return redirect(url_for("index"))


# Example of Organization Switching post-authentication
# This allows a logged in Member on one Organization to "exchange" their
# session for a session on another Organization that they belong to
# all while ensuring that each Organization's authentication requirements are honored
# and respecting data isolation between tenants
@app.route("/switch_orgs")
def switch_orgs():
    session_token = session.get("stytch_session_token", None)
    if session_token is None:
        return redirect(url_for("index"))

    resp = stytch_client.discovery.organizations.list(
        session_token=session.get("stytch_session_token", None)
    )
    if resp.status_code != 200:
        print(resp)
        return "Error listing discovered organizations", 500

    discovered_orgs = resp.discovered_organizations
    orgs = []
    for discovered_org in discovered_orgs:
        orgs.append(
            {
                "organization_id": discovered_org.organization.organization_id,
                "organization_name": discovered_org.organization.organization_name,
            }
        )

    return render_template(
        "discoveredOrganizations.html",
        discovered_organizations=orgs,
        email_address=resp.email_address,
        is_login=False,
        public_token=STYTCH_PUBLIC_TOKEN,
    )


# Example of Organization Login (if logged out)
# Example of Session Exchange (if logged in)
@app.route("/orgs/<string:organization_slug>")
def organization_index(organization_slug):
    member, organization = get_authenticated_member_and_organization()
    if member and organization:
        if organization_slug == organization.organization_slug:
            # User is currently logged into this Organization
            return redirect(url_for("index"))

        # Check to see if User currently belongs to Organization
        resp = stytch_client.discovery.organizations.list(
            session_token=session.get("stytch_session_token", None)
        )
        if resp.status_code != 200:
            print(resp)
            return "Error listing discovered organizations", 500

        discovered_orgs = resp.discovered_organizations
        for discovered_org in discovered_orgs:
            if discovered_org.organization.organization_slug == organization_slug:
                return redirect(
                    url_for(
                        "exchange_into_organization",
                        organization_id=discovered_org.organization.organization_id,
                    )
                )

    # User isn't a current member of Organization, have them login
    resp = stytch_client.organizations.search(
        query=SearchQuery(
            operator="AND",
            operands=[
                {
                    "filter_name": "organization_slugs",
                    "filter_value": [organization_slug],
                }
            ],
        )
    )
    if resp.status_code != 200 or len(resp.organizations) == 0:
        return "Error fetching org by slug", 500

    organization = resp.organizations[0]
    return render_template(
        "organizationLogin.html",
        organization_id=organization.organization_id,
        organization_name=organization.organization_name,
    )


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
    resp = stytch_client.organizations.update(
        organization_id=organization.organization_id,
        email_jit_provisioning="RESTRICTED",
        email_allowed_domains=[domain],
        method_options=UpdateRequestOptions(
            authorization=Authorization(
                session_token=session.get("stytch_session_token", None),
            ),
        ),
    )
    if resp.status_code != 200:
        print(resp)
        return "Error updating Organization JIT Provisioning settings"

    return redirect(url_for("index"))


@app.route("/enroll-mfa", methods=["GET"])
def enroll_mfa():
    return render_template("enrollMFA.html", public_token=STYTCH_PUBLIC_TOKEN)


@app.route("/verify-mfa", methods=["GET"])
def verify_mfa():
    ist = session.get("ist", None)
    organization_id = request.args.get("organization_id")
    visitor_fingerprint = request.args.get("visitor_fingerprint")

    if ist:
        organization = get_organization_from_ist(organization_id)
        print("VMFA - IST Org", organization)
        if not organization:
            return "Organization not found", 404
        member = organization.membership.member
    else:
        member, organization = get_authenticated_member_and_organization()
    if member is None or organization is None:
        return redirect(url_for("index"))

    return render_template(
        "inputMFACode.html",
        organization_id=organization.organization.organization_id,
        member_id=member.member_id,
        form_action=url_for("authenticate_mfa"),
        visitor_fingerprint=visitor_fingerprint,
    )


@app.route("/start-mfa-enrollment", methods=["POST"])
def start_mfa_enrollment():
    phone = request.form.get("phone")
    telemetry_id = request.form.get("telemetry_id")
    member, organization = get_authenticated_member_and_organization()
    if member is None or organization is None:
        return redirect(url_for("index"))

    if not phone or not telemetry_id:
        return "Missing required field", 400

    resp = stytch_client.otps.sms.send(
        organization_id=organization.organization_id,
        member_id=member.member_id,
        mfa_phone_number=phone,
    )

    if resp.status_code != 200:
        return "Error sending MFA code"

    visitor_fingerprint = get_visitor_fingerprint(telemetry_id)

    return render_template(
        "inputMFACode.html",
        organization_id=organization.organization_id,
        member_id=member.member_id,
        form_action=url_for("optional_mfa_enrollment"),
        visitor_fingerprint=visitor_fingerprint,
    )


@app.route("/authenticate-mfa", methods=["POST"])
def authenticate_mfa() -> str:
    code = request.form.get("code", None)
    organization_id = request.form.get("organization_id", None)
    member_id = request.form.get("member_id", None)
    visitor_fingerprint = request.form.get("visitor_fingerprint", None)
    ist = session.get("ist", None)

    logger.info("authenticate_mfa - visitor_fingerprint %s", visitor_fingerprint)

    if member_id is None or organization_id is None:
        return redirect(url_for("index"))

    if code is None:
        return "Missing required field", 400

    ist = session.get("ist")
    if not ist:
        return "No intermediate session token", 400

    resp = stytch_client.otps.sms.authenticate(
        intermediate_session_token=ist,
        code=code,
        organization_id=organization_id,
        member_id=member_id,
    )

    if resp.status_code != 200:
        return "error authenticating mfa", 500

    # Add device to known devices
    add_device_to_known_devices(visitor_fingerprint)

    logger.info("authmfa - pop ist, set session %s", resp.session_token)
    session.pop("ist", None)
    session["stytch_session_token"] = resp.session_token
    return redirect(url_for("index"))


@app.route("/optional-mfa-enrollment", methods=["POST"])
def optional_mfa_enrollment():
    code = request.form.get("code")
    visitor_fingerprint = request.form.get("visitor_fingerprint")
    member, organization = get_authenticated_member_and_organization()

    if member is None or organization is None:
        return redirect(url_for("index"))

    if not code:
        return "Missing required field", 400

    resp = stytch_client.otps.sms.authenticate(
        session_token=session.get("stytch_session_token"),
        code=code,
        organization_id=organization.organization_id,
        member_id=member.member_id,
        set_mfa_enrollment="enroll",
    )

    if resp.status_code != 200:
        return "Error authenticating MFA code"

    # Add device to known devices
    add_device_to_known_devices(visitor_fingerprint)

    logger.info("optional-mfa-enrollment known_devices %s", pformat(known_devices))

    return redirect(url_for("index"))


def get_organization_from_ist(organization_id):
    ist = session.get("ist", None)

    if ist:
        org_list = stytch_client.discovery.organizations.list(
            intermediate_session_token=ist
        )

        # find the organization that matches the organization_id
        organization = next(
            (
                org
                for org in org_list.discovered_organizations
                if org.organization.organization_id == organization_id
            ),
            None,
        )
        if not organization:
            return "Organization not found", 404

        logger.info("IST Organization %s", pformat(organization))
        return organization
    else:
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


def fingerprint_lookup(telemetry_id: str):
    url = f"https://telemetry.stytch.com/v1/fingerprint/lookup?telemetry_id={telemetry_id}"
    auth = (STYTCH_PROJECT_ID, STYTCH_SECRET)

    response = requests.get(url, auth=auth)

    print(response.json())

    if response.status_code == 200:
        resp = response.json()
        # verdict_action = resp["verdict"]["action"]
        # visitor_fingerprint = resp["fingerprints"]["visitor_fingerprint"]
        logger.info("Fingerprint lookup result: %s", pformat(resp))
        return resp
    else:
        return {"error": f"Request failed with status code {response.status_code}"}


def get_visitor_fingerprint(telemetry_id: str) -> str:
    try:
        lookup_result = fingerprint_lookup(telemetry_id)
        return lookup_result["fingerprints"]["visitor_fingerprint"]
    except KeyError:
        logger.error("Failed to get visitor_fingerprint from lookup result")
        return ""
    except Exception as e:
        logger.error(f"Error getting visitor_fingerprint: {e}")
        return ""


def add_device_to_known_devices(visitor_fingerprint: str):
    if visitor_fingerprint:
        if visitor_fingerprint and visitor_fingerprint not in known_devices:
            known_devices.append(visitor_fingerprint)
        logger.info("Known devices updated: %s", pformat(known_devices))


# run's the app on the provided host & port
if __name__ == "__main__":
    # in production you would want to make sure to disable debugging
    app.run(host=HOST, port=PORT, debug=True)
