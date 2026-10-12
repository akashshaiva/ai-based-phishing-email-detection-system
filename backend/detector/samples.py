"""
Preloaded Phishing & Legitimate Email Samples for immediate demonstration and testing.
"""

SAMPLES = [
    {
        "id": "paypal_suspension",
        "title": "PayPal Account Suspension Alert",
        "type": "phishing",
        "category": "Credential Harvesting",
        "sender": "PayPal Resolution Support <service-notice@paypa1-security-verification.xyz>",
        "reply_to": "dispute-case@gmail.com",
        "subject": "URGENT: Your PayPal Account Has Been Suspended [Action Required Within 24 Hours]",
        "body": """Dear Customer,

We have detected unauthorized sign-in attempts on your PayPal account from an unrecognized IP address in Moscow, Russia. 

For your protection, your access has been temporarily restricted. You will not be able to send funds, make purchases, or withdraw balances until your identity is re-authenticated.

FAILURE TO COMPLY WITHIN 24 HOURS WILL RESULT IN PERMANENT ACCOUNT CLOSURE AND LIQUIDATION OF FUNDS.

Click the secure link below to verify your password, billing address, and Social Security Number:
http://paypa1-security-verification.xyz/webscr/login?verify=true

Thank you for your prompt attention,
PayPal Identity Protection Team""",
        "raw_headers": """Received: from mail-phish.net (192.168.1.1)
Received-SPF: fail (domain of paypa1-security-verification.xyz does not designate sender IP)
DKIM-Signature: fail
DMARC: fail"""
    },
    {
        "id": "m365_password_expiry",
        "title": "Microsoft 365 Password Expiration",
        "type": "phishing",
        "category": "Enterprise SSO Harvesting",
        "sender": "Microsoft IT HelpDesk <admin-support@office365-password-reset.top>",
        "reply_to": "",
        "subject": "Your Microsoft Office 365 Corporate Password Expires Today",
        "body": """Attention Employee,

Your Microsoft Office 365 work account password is scheduled to expire in 2 hours. 

If you do not update your password immediately, you will lose access to Outlook Web Mail, Teams chats, and OneDrive corporate cloud storage.

Keep your current password by confirming your active credentials here:
http://office365-password-reset.top/auth/sso/login

Do not ignore this notification.
IT Infrastructure Services""",
        "raw_headers": """Received-SPF: fail
DKIM-Signature: none"""
    },
    {
        "id": "dhl_delivery_fee",
        "title": "DHL Express Delivery Tracking Hold",
        "type": "phishing",
        "category": "Smishing / Package Scam",
        "sender": "DHL Express Tracking <parcel-tracking@dhl-customs-clearance.buzz>",
        "reply_to": "",
        "subject": "DHL Express: Package #9948210 cannot be delivered due to unpaid customs fee",
        "body": """Dear Customer,

Your parcel shipment tracking code #9948210-US is currently on hold at our regional customs sorting facility.

An outstanding customs declaration fee of $2.95 USD must be paid within 12 hours before our courier can schedule final doorstep delivery.

Pay the remaining customs balance and update your residential address here:
http://dhl-customs-clearance.buzz/tracking/pay-invoice

If unpaid, the package will be returned to the international merchant at your expense.

Regards,
DHL Global Express Logistics""",
        "raw_headers": """Received-SPF: fail"""
    },
    {
        "id": "ceo_gift_card",
        "title": "CEO Urgent Wire / Gift Card Fraud",
        "type": "phishing",
        "category": "Business Email Compromise (BEC)",
        "sender": "Jonathan Reynolds (CEO) <ceo.jonathanreynolds992@gmail.com>",
        "reply_to": "ceo.jonathanreynolds992@gmail.com",
        "subject": "Are you at your desk right now? Need urgent assistance",
        "body": """Hi,

Are you at your desk right now? I am currently tied up in an all-day executive board meeting and cannot take phone calls.

I urgently need you to handle a quick task for a VIP client presentation this afternoon. Can you go purchase 5 Apple Store gift cards of $100 each from the nearest store? 

Scratch the back, take clear photos of the codes, and email them back to my personal email right away. I will approve your expense reimbursement form as soon as I exit the boardroom.

Please treat this with high priority and confidentiality.

Thanks,
Jonathan Reynolds
Chief Executive Officer""",
        "raw_headers": """Received: from mail.google.com"""
    },
    {
        "id": "legit_github_digest",
        "title": "GitHub Weekly Activity Digest",
        "type": "legitimate",
        "category": "Standard Notification",
        "sender": "GitHub Notifications <notifications@github.com>",
        "reply_to": "support@github.com",
        "subject": "[GitHub] Weekly digest for your subscribed repositories",
        "body": """Hello developer,

Here is your weekly summary of activity across repositories you contribute to:

- 18 Pull Requests merged in main branch
- 4 Issues closed this week
- 2 Releases published: v2.4.0 and v2.4.1

To view commit history or manage your notification preferences, visit your GitHub settings dashboard:
https://github.com/settings/notifications

Happy coding!
The GitHub Team""",
        "raw_headers": """Received-SPF: pass (domain of github.com designates 192.30.252.206 as permitted sender)
DKIM-Signature: pass
DMARC: pass"""
    },
    {
        "id": "legit_calendar_invite",
        "title": "Sprint Planning Meeting Invitation",
        "type": "legitimate",
        "category": "Internal Corporate Sync",
        "sender": "David Miller <david.miller@company.org>",
        "reply_to": "david.miller@company.org",
        "subject": "Invitation: Sprint 44 Planning & Backlog Grooming @ Thu 2pm - 3pm",
        "body": """Hi team,

You are invited to join the bi-weekly Sprint 44 Planning meeting.

When: Thursday, October 15, 2026, 2:00 PM - 3:00 PM EST
Where: Google Meet / Conference Room 4B

Agenda:
1. Review completed user stories from Sprint 43
2. Estimate velocity for Q4 milestones
3. Prioritize architectural spikes and UI improvements

Please review the Jira backlog prior to the session so we can jump right into estimations.

Best regards,
David Miller
Senior Product Manager""",
        "raw_headers": """Received-SPF: pass
DKIM-Signature: pass
DMARC: pass"""
    }
]
