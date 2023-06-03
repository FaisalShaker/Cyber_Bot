from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
import random


class ActionScanViruses(Action):
    def name(self) -> Text:
        return "action_scan_viruses"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Simulate scanning process
        is_virus_found = random.choice([True, False])

        if is_virus_found:
            dispatcher.utter_message(template="utter_virus_found")
        else:
            dispatcher.utter_message(template="utter_no_virus_found")

        return []

class ActionScanMalware(Action):
    def name(self) -> Text:
        return "action_scan_malware"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Simulate scanning process
        is_malware_found = random.choice([True, False])

        if is_malware_found:
            dispatcher.utter_message(template="utter_malware_found")
        else:
            dispatcher.utter_message(template="utter_no_malware_found")

        return []

class ActionUpdateSoftware(Action):
    def name(self) -> Text:
        return "action_update_software"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to update software
        dispatcher.utter_message(template="utter_update_software")
        return []


class ActionEnableFirewall(Action):
    def name(self) -> Text:
        return "action_enable_firewall"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to enable firewall
        dispatcher.utter_message(template="utter_recommend_firewall")
        return []


class ActionInstallAntivirus(Action):
    def name(self) -> Text:
        return "action_install_antivirus"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to install antivirus
        dispatcher.utter_message(template="utter_install_antivirus")
        return []



class ActionAskFirewallRecommendation(Action):
    def name(self) -> Text:
        return "action_ask_firewall_recommendation"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        operating_system = tracker.latest_message.get('text')  # Extract operating system from user input

        # Logic to provide firewall recommendations based on operating system
        dispatcher.utter_message(template="utter_ask_firewall_recommendation")
        return []


class ActionAskSoftwareUpdateFrequency(Action):
    def name(self) -> Text:
        return "action_ask_software_update_frequency"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        software = tracker.latest_message.get('text')  # Extract software name from user input

        # Logic to provide software update frequency advice
        dispatcher.utter_message(template="utter_ask_software_update_frequency")
        return []


class ActionAskPasswordBestPractices(Action):
    def name(self) -> Text:
        return "action_ask_password_best_practices"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide password best practices
        dispatcher.utter_message(template="utter_ask_password_best_practices")
        return []


class ActionAskSecurityBreachResponse(Action):
    def name(self) -> Text:
        return "action_ask_security_breach_response"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide security breach response guidance
        dispatcher.utter_message(template="utter_ask_security_breach_response")
        return []


class ActionAskDataBackupMethods(Action):
    def name(self) -> Text:
        return "action_ask_data_backup_methods"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        data_type = tracker.latest_message.get('text')  # Extract data type from user input

        # Logic to provide data backup methods based on data type
        dispatcher.utter_message(template="utter_ask_data_backup_methods")
        return []


class ActionAskSafeBrowsingTips(Action):
    def name(self) -> Text:
        return "action_ask_safe_browsing_tips"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide safe browsing tips
        dispatcher.utter_message(template="utter_ask_safe_browsing_tips")
        return []


class ActionAskPhishingPrevention(Action):
    def name(self) -> Text:
        return "action_ask_phishing_prevention"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide phishing prevention tips
        dispatcher.utter_message(template="utter_ask_phishing_prevention")
        return []


class ActionAskSocialEngineeringAwareness(Action):
    def name(self) -> Text:
        return "action_ask_social_engineering_awareness"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide social engineering awareness information
        dispatcher.utter_message(template="utter_ask_social_engineering_awareness")
        return []


class ActionAskNetworkSecurityTips(Action):
    def name(self) -> Text:
        return "action_ask_network_security_tips"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        is_wireless = tracker.latest_message.get('text')  # Extract wireless network information from user input

        # Logic to provide network security tips based on network type
        dispatcher.utter_message(template="utter_ask_network_security_tips")
        return []


class ActionAskMobileDeviceSecurity(Action):
    def name(self) -> Text:
        return "action_ask_mobile_device_security"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        mobile_os = tracker.latest_message.get('text')  # Extract mobile OS from user input

        # Logic to provide mobile device security tips based on mobile OS
        dispatcher.utter_message(template="utter_ask_mobile_device_security")
        return []


class ActionReportIncident(Action):
    def name(self) -> Text:
        return "action_report_incident"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to handle reporting security incidents or data breaches
        dispatcher.utter_message(template="utter_report_incident")
        return []


class ActionRecoverHackedAccount(Action):
    def name(self) -> Text:
        return "action_recover_hacked_account"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide guidance for recovering a hacked account
        dispatcher.utter_message(template="utter_recover_hacked_account")
        return []


class ActionAskAboutPhishing(Action):
    def name(self) -> Text:
        return "action_ask_about_phishing"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide information about phishing
        dispatcher.utter_message(template="utter_ask_about_phishing")
        return []


class ActionAskAboutMalware(Action):
    def name(self) -> Text:
        return "action_ask_about_malware"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide information about malware
        dispatcher.utter_message(template="utter_ask_about_malware")
        return []


class ActionAskAboutRansomware(Action):
    def name(self) -> Text:
        return "action_ask_about_ransomware"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide information about ransomware
        dispatcher.utter_message(template="utter_ask_about_ransomware")
        return []


class ActionAskAboutDataPrivacy(Action):
    def name(self) -> Text:
        return "action_ask_about_data_privacy"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide information about data privacy
        dispatcher.utter_message(template="utter_ask_about_data_privacy")
        return []


class ActionAskAboutSocialMediaSecurity(Action):
    def name(self) -> Text:
        return "action_ask_about_social_media_security"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide information about social media security
        dispatcher.utter_message(template="utter_ask_about_social_media_security")
        return []


class ActionAskAboutMultiFactorAuthentication(Action):
    def name(self) -> Text:
        return "action_ask_about_multi_factor_authentication"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Logic to provide information about multi-factor authentication
        dispatcher.utter_message(template="utter_ask_about_multi_factor_authentication")
        return []

class ActionAskAboutCybersecurity(Action):
    def name(self) -> Text:
        return "action_ask_about_cybersecurity"

    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        dispatcher.utter_message(template="utter_ask_about_cybersecurity")

        return []
    

class ActionGiveCybersecurityAdvice(Action):
    def name(self) -> Text:
        return "action_give_cybersecurity_advice"

    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        tips = [
            "Use strong and unique passwords for all your accounts.",
            "Enable multi-factor authentication whenever possible.",
            "Keep your devices and software up to date with the latest security patches.",
            "Be cautious of suspicious emails, messages, and websites. Avoid clicking on links or downloading attachments from unknown sources.",
            "Use reputable antivirus and anti-malware software and keep them updated.",
            "Regularly back up your important data to a secure location.",
            "Be mindful of your online activities and avoid sharing sensitive information unnecessarily.",
            "Educate yourself about common cyber threats and stay informed about the latest security practices.",
            "Use a virtual private network (VPN) when connecting to public Wi-Fi networks.",
            "Secure your home network by changing the default router password and enabling network encryption.",
            "Regularly review your privacy settings on social media platforms and adjust them to your desired level of privacy.",
            "Be cautious of phishing emails: Avoid clicking on suspicious links or providing personal information in response to unsolicited emails. Verify the sender's identity before taking any action.",
            "Use a password manager: Consider using a password manager to securely store and generate unique passwords for your online accounts. This helps prevent password reuse and enhances overall account security.",
            "Enable automatic software updates: Enable automatic updates for your operating system, applications, and security software. This ensures you have the latest security patches and bug fixes to protect against known vulnerabilities.",
            "Regularly review your privacy settings: Regularly review and update the privacy settings on your devices, social media accounts, and other online platforms. Limit the amount of personal information you share and adjust privacy controls according to your preferences."
            "Secure your home network: Change the default password on your Wi-Fi router, enable WPA2 or WPA3 encryption, and use a strong network password. Also, consider using a firewall and regularly update your router's firmware.",
            "Backup your data: Regularly backup your important files and data to an external hard drive, cloud storage, or another secure location. This ensures you can recover your data in case of accidental deletion, hardware failure, or ransomware attacks.",
            "Use secure browsing practices: Look for the padlock icon and 'https' in the URL when visiting websites to ensure a secure connection. Avoid accessing sensitive information or making financial transactions on unsecured or public Wi-Fi networks.",
            "Be mindful of social media sharing: Be cautious about the personal information you share on social media platforms. Avoid disclosing sensitive details such as your full address, phone number, or vacation plans, as this information can be used for malicious purposes.",
            "Implement strong email security measures: Enable two-factor authentication for your email accounts and be wary of suspicious email attachments or requests for personal information. Regularly scan your email for phishing attempts and report any suspicious emails to your email provider.",
            "Educate yourself about cybersecurity: Stay informed about the latest cybersecurity threats, trends, and best practices. Read reputable sources, attend webinars or workshops, and follow cybersecurity experts and organizations on social media to stay updated."
        ]
        
        advice = random.choice(tips)
        response = f"Here's a cybersecurity advice: {advice}"
        
        dispatcher.utter_message(text=response)

        return []