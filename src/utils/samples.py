"""Curated benchmark samples for threat detection and offline testing.

This module provides a diverse, realistic dataset of phishing, spear-phishing,
social engineering, and benign corporate communications for testing and benchmarking
natural language threat detection models, heuristic rule engines, and security guardrails.
"""

from __future__ import annotations

from typing import Literal, TypedDict

SampleLabel = Literal["malicious", "suspicious", "benign"]


class ThreatSample(TypedDict):
    """Schema definition for a threat benchmark sample."""

    label: SampleLabel
    category: str
    text: str
    description: str


THREAT_SAMPLES: list[ThreatSample] = [
    {
        "label": "malicious",
        "category": "Credential Harvest",
        "description": "Microsoft 365 Urgent Password Expiration Notice",
        "text": (
            "From: IT Service Desk <notifications@microsoft-365-verify.com>\n"
            "Subject: URGENT: Your Microsoft 365 Password Expires in 2 Hours\n\n"
            "Dear Employee,\n\n"
            "Your Microsoft 365 corporate account password will expire today at 5:00 PM EST. "
            "To prevent loss of email access and active Teams sessions, you must retain your "
            "current password immediately by verifying your identity.\n\n"
            "Please click the secure link below to authenticate and keep your current credentials:\n"
            "http://microsoft-365-verify.com/auth?user=session_renewal\n\n"
            "Failure to verify will result in immediate suspension of all corporate cloud resources.\n\n"
            "Regards,\n"
            "Global IT Infrastructure Team"
        ),
    },
    {
        "label": "malicious",
        "category": "CEO Fraud",
        "description": "Executive Impersonation Confidential Wire Acquisition",
        "text": (
            "From: Richard Henderson <ceo.henderson.executive@gmail.com>\n"
            "To: finance-ops@company.com\n"
            "Subject: Confidential Project Falcon - Immediate Wire Required\n\n"
            "Hi team,\n\n"
            "I am currently in an off-site board meeting for the acquisition of our European competitor "
            "(Project Falcon). Due to strict regulatory non-disclosure rules, this matter is strictly "
            "confidential.\n\n"
            "I need an urgent escrow payment of $148,500 routed before 3:00 PM today to secure the asset. "
            "Do not discuss this on Slack or over the phone as it violates our quiet period. Please reply "
            "directly to this email so I can send the wiring beneficiary coordinates.\n\n"
            "Best regards,\n"
            "Richard Henderson\n"
            "Chief Executive Officer"
        ),
    },
    {
        "label": "malicious",
        "category": "Account Suspension",
        "description": "AWS Cloud Production Account Suspension Notice",
        "text": (
            "From: AWS Notification Service <no-reply@secure-verify-account.xyz>\n"
            "Subject: CRITICAL: Immediate AWS Account Suspension Notice #AWS-99214\n\n"
            "Attention Root Administrator,\n\n"
            "We were unable to process your recurring monthly billing payment for AWS Cloud Services. "
            "Your production compute instances and Amazon RDS databases are scheduled for termination "
            "within 24 hours to prevent unpaid resource utilization.\n\n"
            "To preserve your active workloads and avoid data deletion, review and update your billing profile:\n"
            "http://secure-verify-account.xyz/login?action=revalidate_billing\n\n"
            "Amazon Web Services Cloud Billing Support"
        ),
    },
    {
        "label": "malicious",
        "category": "Invoice Fraud",
        "description": "Vendor Payment Remittance with Updated Bank Account",
        "text": (
            "From: Accounts Receivable <billing@acme-logistics-corp.biz>\n"
            "Subject: Overdue Invoice #INV-98421 - Updated Wire Banking Details\n\n"
            "Dear Valued Partner,\n\n"
            "Please find attached the revised invoice #INV-98421 for the amount of $42,390.00. "
            "Note that due to our recent annual banking audit, our remittance account has been changed "
            "effective immediately. Any payment sent to our previous account will fail and incur late penalties.\n\n"
            "Download and inspect the signed payment schedule at:\n"
            "http://invoices-portal-quickbooks.biz/download?id=98421&auth=direct\n\n"
            "Kindly confirm once the wire transfer confirmation receipt is generated.\n\n"
            "Sincerely,\n"
            "Karen Mitchell | Finance Operations Manager"
        ),
    },
    {
        "label": "malicious",
        "category": "Spear Phishing",
        "description": "Confidential HR Annual Compensation Review Link",
        "text": (
            "From: People & Culture Department <hr-announcements@hr-portal-securelogin.info>\n"
            "Subject: Confidential: Your 2026 Merit Increase and Executive Bonus Allocation\n\n"
            "Hello,\n\n"
            "The executive leadership committee has completed the annual compensation cycle. "
            "Your revised compensation package, equity vesting adjustment, and bonus letter are now ready "
            "for confidential review.\n\n"
            "To review your personalized compensation statement, please authenticate with your single sign-on credentials:\n"
            "http://hr-portal-securelogin.info/benefits/review?token=emp_77219\n\n"
            "This link is uniquely signed for your profile and expires in 48 hours.\n\n"
            "People Operations Team"
        ),
    },
    {
        "label": "malicious",
        "category": "Wire Transfer Scam",
        "description": "Time-Sensitive Escrow Wire Details for Commercial Closing",
        "text": (
            "From: First Commercial Title & Escrow <settlement@escrow-title-settlement.com>\n"
            "Subject: TIME SENSITIVE: Final Settlement Statement & Escrow Instructions\n\n"
            "Attention Buyer / Accounting,\n\n"
            "Due to an unexpected system routing issue with our primary depository bank, the wiring "
            "instructions provided in the preliminary closing packet are null and void. Please route the "
            "required down-payment balance of $210,000 to our alternate clearing partner specified in the portal:\n\n"
            "Access Escrow Portal: http://secure-verify-account.xyz/escrow/instructions?id=984102\n\n"
            "Wiring must be executed before 1:00 PM EST to avoid defaulting on the closing agreement.\n\n"
            "Closing & Escrow Department"
        ),
    },
    {
        "label": "malicious",
        "category": "Tax Fraud",
        "description": "IRS Form W-2 Correction Mandate and Wage Verification",
        "text": (
            "From: Internal Revenue Service Notification <irs-notice@irs-tax-refund-portal.org>\n"
            "Subject: Official Notice: Incomplete Form W-2 Wage and Tax Statement\n\n"
            "Notice CP05A - Immediate Action Required\n\n"
            "We have detected discrepancies between your employer's reported wages and your electronic "
            "tax return filings. Under federal statute, failure to verify your Social Security Number and "
            "withholding credentials will result in withholding penalties and referral to enforcement.\n\n"
            "Access the IRS Electronic Wage Verification Gateway below:\n"
            "http://irs-tax-refund-portal.org/w2verify?ref=CP05A-2026\n\n"
            "Internal Revenue Service | Department of the Treasury"
        ),
    },
    {
        "label": "malicious",
        "category": "Smishing",
        "description": "USPS Package Delivery Failure Fee Request",
        "text": (
            "USPS Tracking: Package #US9400109202 is on hold at the distribution center due to an invalid "
            "house number. A redelivery fee of $1.85 is required within 12 hours to avoid return to sender. "
            "Confirm your address and complete payment at: http://usps-track-parcel-update.com/claim"
        ),
    },
    {
        "label": "malicious",
        "category": "Credential Harvest",
        "description": "DocuSign Secure Electronic Envelope Signature Request",
        "text": (
            "From: DocuSign Signature Service <noreply@docusign-secure-document-review.top>\n"
            "Subject: Please DocuSign: 2026 Corporate_Bonus_Restructuring_Agreement.pdf\n\n"
            "All parties have completed their review. Your signature is required to finalize execution.\n\n"
            "Review and Sign Document:\n"
            "http://docusign-secure-document-review.top/envelope/auth?id=DOC-4892019\n\n"
            "This link will expire in 2 hours for security reasons. Do not forward this email.\n\n"
            "Powered by DocuSign Cloud Security"
        ),
    },
    {
        "label": "suspicious",
        "category": "CEO Fraud",
        "description": "Informal Executive SMS Outreach Requesting Gift Cards",
        "text": (
            "From: David Sterling (Personal Phone) <+1-555-019-3382>\n"
            "To: operations-lead@company.com\n"
            "Subject: Quick favor - Are you at your desk?\n\n"
            "Hey, are you free right now? I am tied up in a client conference and can't take phone calls. "
            "I need you to pick up five Apple gift cards ($200 each) for an emergency client giveaway prize. "
            "Please scratch off the codes and send photos of the back directly to this email. I will have "
            "accounting reimburse you on tomorrow's expense run.\n\n"
            "Thanks,\nDavid"
        ),
    },
    {
        "label": "suspicious",
        "category": "Smishing",
        "description": "Banking Fraud Alert SMS Prompting Verification Link",
        "text": (
            "CHASE ALERT: Did you authorize a debit charge of $1,429.99 at BEST BUY STORE #412? "
            "If YES reply 1. If NO, immediately verify your account security to prevent unauthorized withdrawal: "
            "http://chase-security-check.xyz/alert?case=88124"
        ),
    },
    {
        "label": "suspicious",
        "category": "Spear Phishing",
        "description": "IT Helpdesk Mandatory Multifactor Authentication Migration",
        "text": (
            "From: Corporate IT Security Operations <it-support@it-support-sso-gateway.co>\n"
            "Subject: Mandatory Security Upgrade: Migrate to Okta FastPass MFA\n\n"
            "Team,\n\n"
            "In accordance with our zero-trust security policy, all personnel must register their hardware "
            "tokens and biometric keys by end of business day. Accounts not enrolled by 6:00 PM will be "
            "locked out from VPN and email access.\n\n"
            "Complete your migration here:\n"
            "http://it-support-sso-gateway.co/mfa-setup?enrolment_id=sec_99182\n\n"
            "Security Operations Center"
        ),
    },
    {
        "label": "benign",
        "category": "Benign Newsletter",
        "description": "Engineering Weekly Tech Digest and Architecture Highlights",
        "text": (
            "From: Engineering All <tech-digest@company.internal>\n"
            "Subject: Engineering Weekly #42: Python 3.12 Upgrades & Distributed Tracing\n\n"
            "Hello Engineers,\n\n"
            "Welcome to this week's edition of the Tech Digest!\n\n"
            "Highlights for this sprint:\n"
            "1. Python 3.12 Migration: Core platform services achieved a 14% latency drop after enabling "
            "PEP 684 per-interpreter GIL and specialized bytecode opcodes.\n"
            "2. OpenTelemetry Rollout: Distributed tracing is now live across all staging clusters. Check out "
            "the Grafana dashboards on our internal wiki.\n"
            "3. Book Club: We are reading 'Designing Data-Intensive Applications' by Martin Kleppmann on Thursdays.\n\n"
            "Have an article or architecture proposal to share? Post it on the #eng-general Slack channel!\n\n"
            "Best,\n"
            "Developer Experience Team"
        ),
    },
    {
        "label": "benign",
        "category": "Benign Internal",
        "description": "Q3 Corporate All-Hands Meeting Invitation & Slide Deck",
        "text": (
            "From: Internal Communications <internal-comms@company.com>\n"
            "Subject: Invitation: Q3 Global All-Hands Meeting & Strategy Update\n\n"
            "Dear Team,\n\n"
            "Please join us this Thursday at 10:00 AM PST for our quarterly company-wide All-Hands meeting. "
            "Executive leadership will provide updates on Q3 revenue targets, customer success milestones, "
            "and product roadmaps for the upcoming fiscal quarter.\n\n"
            "Meeting Details:\n"
            "- When: Thursday, Oct 15, 2026, 10:00 AM - 11:30 AM PST\n"
            "- Location: Main Auditorium (San Francisco HQ) / Zoom Webinar ID: 948-281-992\n"
            "- Slido Q&A: Submit questions in advance using hashtag #Q3AllHands\n\n"
            "The slide presentation and meeting recording will be uploaded to Confluence following the broadcast.\n\n"
            "Best regards,\n"
            "Internal Communications Team"
        ),
    },
    {
        "label": "benign",
        "category": "Benign Customer Service",
        "description": "Customer Support Ticket Resolution and Feedback Request",
        "text": (
            "From: TerGuard Customer Support <support@terguard.ai>\n"
            "Subject: Resolved: Support Ticket #48291 - API Webhook Configuration\n\n"
            "Hi Michael,\n\n"
            "This is an automated notification that your support ticket #48291 has been marked as resolved "
            "by our technical support team. Our engineers verified that the payload signing secret has been "
            "re-synced with your production tenant.\n\n"
            "If your issue has not been resolved to your satisfaction, simply reply directly to this email "
            "within 5 business days to reopen the ticket.\n\n"
            "Documentation & Knowledge Base: https://docs.terguard.ai/webhooks/security\n\n"
            "Thank you for choosing TerGuard AI,\n"
            "Customer Support Operations"
        ),
    },
    {
        "label": "benign",
        "category": "Benign Internal",
        "description": "Facilities Scheduled Maintenance Notification",
        "text": (
            "From: Facilities Operations <facilities@company.com>\n"
            "Subject: Notice: Scheduled HVAC and Power Maintenance This Weekend\n\n"
            "Good afternoon,\n\n"
            "Please be advised that scheduled preventative maintenance will take place in Building B this "
            "Saturday, October 10th, from 8:00 AM to 4:00 PM.\n\n"
            "Key Information:\n"
            "- Heating and air conditioning services will be temporarily suspended in Building B.\n"
            "- Elevator #2 will be reserved for maintenance technicians during this period.\n"
            "- Keycard security access remains active across all exterior entry points.\n\n"
            "If you plan to work on-site over the weekend, we recommend utilizing Building A workspaces.\n\n"
            "Facilities Management"
        ),
    },
    {
        "label": "benign",
        "category": "Benign Newsletter",
        "description": "Company Weekly Pulse, Core Values Awards & Shout-outs",
        "text": (
            "From: Culture & Engagement <pulse@company.com>\n"
            "Subject: The Weekly Pulse: Celebrating Team Milestones & Q3 Hackathon Winners\n\n"
            "Happy Friday Everyone!\n\n"
            "Before we sign off for the weekend, let's celebrate this week's remarkable team accomplishments:\n\n"
            "- Hackathon Grand Prize: Congratulations to Team 'Neural Shield' for their real-time telemetry model!\n"
            "- Work Anniversaries: Celebrating Sarah Jenkins (5 years) and Carlos Ortiz (3 years)!\n"
            "- Wellness Day: Reminder that next Friday is a designated company-wide rest day.\n\n"
            "Wishing everyone a restful and productive weekend!\n\n"
            "People & Culture Team"
        ),
    },
    {
        "label": "benign",
        "category": "Benign Customer Service",
        "description": "Verified Hardware Order Confirmation and Tracking Receipt",
        "text": (
            "From: Dell Enterprise Hardware <orders@dell-enterprise.com>\n"
            "Subject: Order Confirmation #ORD-881924 - Dell PowerEdge R760 Server Rack\n\n"
            "Dear IT Procurement Department,\n\n"
            "Thank you for your order. We have received your purchase order #PO-2026-992 and payment has "
            "been authorized according to your corporate master services agreement.\n\n"
            "Order Summary:\n"
            "- Item: Dell PowerEdge R760 Rack Server (x2)\n"
            "- Delivery Address: Data Center 4, 100 Industrial Pkwy, Austin TX\n"
            "- Estimated Delivery: Wednesday, Oct 21, 2026\n\n"
            "You can track your package shipment and review your invoice receipt online at:\n"
            "https://www.dell.com/orders/tracking?id=ORD-881924\n\n"
            "Dell Enterprise Systems Team"
        ),
    },
]


PRESET_ATTACK_VECTORS: dict[str, str] = {
    sample["description"]: sample["text"] for sample in THREAT_SAMPLES
}


def get_samples_by_label(label: str) -> list[ThreatSample]:
    """Return all threat benchmark samples matching the given classification label.

    The comparison is case-insensitive. Valid labels typically include 'malicious',
    'suspicious', and 'benign'.

    Args:
        label: The classification label to filter by (e.g., 'malicious', 'suspicious', 'benign').

    Returns:
        A list of ThreatSample dictionaries matching the label.
    """
    normalized_label = label.strip().lower()
    return [
        sample for sample in THREAT_SAMPLES
        if sample["label"].lower() == normalized_label
    ]


def get_sample_names() -> list[str]:
    """Return a list of display description strings for all benchmark samples.

    These names can be used to populate selection menus and user interface dropdowns.

    Returns:
        A list of sample description strings.
    """
    return [sample["description"] for sample in THREAT_SAMPLES]


def get_samples_by_category(category: str) -> list[ThreatSample]:
    """Return all threat benchmark samples matching a specific threat category.

    The comparison is case-insensitive.

    Args:
        category: The category name (e.g., 'CEO Fraud', 'Credential Harvest', 'Smishing').

    Returns:
        A list of matching ThreatSample dictionaries.
    """
    normalized_category = category.strip().lower()
    return [
        sample for sample in THREAT_SAMPLES
        if sample["category"].lower() == normalized_category
    ]


def get_sample_by_name(name: str) -> ThreatSample | None:
    """Retrieve a single benchmark sample by its exact description name.

    Args:
        name: The description name of the sample.

    Returns:
        The matching ThreatSample dictionary, or None if not found.
    """
    for sample in THREAT_SAMPLES:
        if sample["description"] == name:
            return sample
    return None
