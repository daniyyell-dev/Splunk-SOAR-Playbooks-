import phantom.rules as phantom

import requests

# Define the playbook

def on_start(container):

    phantom.debug('exfiltration investigation playbook')

    phantom.set_severity(container=container, severity="high")

    phantom.pin(container=container, label="Data Exfiltration Investigation")

    # Extract the affected asset and file path

    asset = phantom.get_artifact(container, 'asset')

    file_path = phantom.get_artifact(container, 'file')

    # Look for suspicious network activity

    suspicious_ips = []

    network_artifacts = phantom.get_artifacts(container, 'network')

    for artifact in network_artifacts:

        if artifact['cef']['dst'] == asset['cef']['name']:

            suspicious_ips.append(artifact['cef']['saddr'])

    if len(suspicious_ips) > 0:

        # Mark the container as containing suspicious network activity

        phantom.add_tag(container, 'data_exfiltration:suspicious_network')

        phantom.set_status(container, 'open')

        phantom.add_note(container, f"Suspicious network activity detected to {', '.join(suspicious_ips)}.")

    # Look for suspicious file activity

    file_artifacts = phantom.get_artifacts(container, 'file')

    for artifact in file_artifacts:

        if artifact['cef']['act'] == 'write':

            if artifact['cef']['fname'] == file_path['cef']['name']:

                # Mark the container as containing suspicious file activity

                phantom.add_tag(container, 'data_exfiltration:suspicious_file')

                phantom.set_status(container, 'open')

                phantom.add_note(container, f"Suspicious file activity detected on {file_path['cef']['name']}.")

    # Check if the file was actually exfiltrated

    if phantom.find_events(container, search_fields="dest_file_path=\"{}\"".format(file_path['cef']['name'])):

        # Mark the container as containing confirmed data exfiltration

        phantom.add_tag(container, 'data_exfiltration:confirmed')

        phantom.set_status(container, 'closed')

        phantom.add_note(container, f"Confirmed data exfiltration of {file_path['cef']['name']}.")

        # Take actions to contain the incident

        quarantine_asset(asset['cef']['name'])

        disable_user(asset['cef']['owner'])

        notify_security_team(file_path['cef']['name'])

    phantom.debug('exfiltration investigation playbook completed.')

def quarantine_asset(asset_name):

    phantom.debug(f"Quarantining asset: {asset_name}")

    # Code to quarantine the asset goes here

    # ...check your splunk SOAR APP

def disable_user(username):

    phantom.debug(f"Disabling user account: {username}")

    # Code to disable the user account goes here

    # ...check your SPLUNK SOAR app

def notify_security_team(file_name):

    phantom.debug(f"Notifying security team about data exfiltration: {file_name}")

    # Code to notify the security team goes here

    # ... check YOUR Splunk SOAR app

