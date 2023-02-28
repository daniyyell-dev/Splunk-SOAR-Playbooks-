import phantom.rules as phantom

# Define the playbook
def on_start(container):
    phantom.debug('Starting the phishing investigation playbook')
    phantom.set_severity(container=container, severity="high")
    phantom.pin(container=container, label="Phishing Investigation")

    # Create a new artifact
    artifact = phantom.get_artifact(container, 'email')

    # Extract the email headers
    headers = artifact['cef']['headers']
    subject = headers.get('Subject', '')
    sender = headers.get('From', '')
    recipient = headers.get('To', '')
    message_id = headers.get('Message-ID', '')

    # Check for known phishing indicators
    if 'PayPal' in subject or 'PayPal' in sender:
        phantom.add_tag(container, 'phishing:paypal')
        phantom.set_status(container, 'closed')
        phantom.add_note(container, 'This email contains known phishing indicators for PayPal.')

    elif 'IRS' in subject or 'IRS' in sender:
        phantom.add_tag(container, 'phishing:irs')
        phantom.set_status(container, 'closed')
        phantom.add_note(container, 'This email contains known phishing indicators for the IRS.')

    elif 'Amazon' in subject or 'Amazon' in sender:
        phantom.add_tag(container, 'phishing:amazon')
        phantom.set_status(container, 'closed')
        phantom.add_note(container, 'This email contains known phishing indicators for Amazon.')

    else:
        # No known phishing indicators found
        phantom.add_tag(container, 'phishing:unknown')
        phantom.set_status(container, 'open')
        phantom.add_note(container, 'No known phishing indicators found for this email.')
        
    phantom.debug('Phishing investigation playbook completed.')
