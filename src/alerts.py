import boto3
import os
import threading
from datetime import datetime
from database import set_cooldown, get_cooldown, save_subscription, delete_subscription, get_all_subscriptions
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class AlertManager:

    """Manages AWS SNS subscriptions and sends alerts when malicious flows are detected by the NIDS.
    Subscriptions are stored in a SQLite database to persist across sessions."""

    def __init__(self, region = 'eu-west-1', test_mode = False):

        """Initializes the AlertManager by setting up the SNS client and loading existing subscriptions from database."""

        #If test_mode = true - AlertManager will only print to console instead of sending actual SMS alerts
        self.test_mode = test_mode
        if test_mode:
            print("Running in test mode - Actual SMS alerts will not be sent.")

        self.sns = boto3.client(
            'sns',
            region_name = region,
            aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key = os.getenv('AWS_SECRET_KEY')
        )

        #SNS topic ARN should be set in environment variables for the AlertManager to function properly.
        self.topic_arn = os.getenv('SNS_TOPIC_ARN')

        if not self.topic_arn:
            raise ValueError("SNS_TOPIC_ARN environment variable not set.")

        #Store 5 minutes alert cooldown cache to stop alert spam.
        self._cooldowns = {}
        self.cooldown_seconds = 300

        #Forces threads to wait for each other when accessing cooldown cache to prevent duplicate alerts
        self._lock = threading.Lock()
    
    def _should_alert(self, label, src_ip):

        """Checks if an alert should be sent or not if it still in its cooldown period."""

        with self._lock:

            last = get_cooldown(src_ip, label)

            if last:
                elapsed_time = (datetime.now() - last).total_seconds()

                if elapsed_time < self.cooldown_seconds:
                    remaining = self.cooldown_seconds - elapsed_time

                    print (f"[ALERT COOLDOWN] Duplicate alert detected: {label} from {src_ip} | {remaining:.0f}s remaining on alert cooldown.")
                    return False
            
            set_cooldown(src_ip, label)
            return True

    def subscribe(self, phone_number):

        """Subscribes a phone number to the SNS topic to receive SMS alerts. Returns True if successful, False otherwise."""

        try:
            subs = get_all_subscriptions()

            if phone_number in subs:
                print(f"{phone_number} is already subscribed.")
                return False
            
            response = self.sns.subscribe(
                TopicArn = self.topic_arn,
                Protocol = 'sms',
                Endpoint = phone_number
            )

            save_subscription(phone_number, response['SubscriptionArn'])
            print(f"Subscribed {phone_number} successfully.")
            return True
        
        except Exception as e:
            print(f"Error occurred while subscribing {phone_number}: {e}")
            return False
    
    def unsubscribe(self, phone_number):

        """Unsubscribes a phone number from the SNS topic. Returns True if successful, False otherwise."""

        try:

            subs = get_all_subscriptions()

            if phone_number not in subs:
                print(f"{phone_number} is not subscribed.")
                return False
            
            self.sns.unsubscribe(SubscriptionArn=subs[phone_number])
            delete_subscription(phone_number)

            print(f"Unsubscribed {phone_number} successfully.")
            return True
        
        except Exception as e:
            print(f"Error occurred while unsubscribing {phone_number}: {e}")
            return False
        
    def get_subscriptions(self):

        """Returns a list of currently subscribed phone numbers."""

        return list(get_all_subscriptions().keys())
    
    def send_alert(self, label, confidence, src_ip, dst_ip, src_port, dst_port, protocol):

        """Sends an alert via SNS with the details of the detected attack. Returns True if successful, False otherwise."""

        if not self._should_alert(label, src_ip):
            return False
        
        if self.test_mode:
            print(f"[TEST MODE] would send SMS: {label} ({confidence:.2f}%) {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return True

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            message = (
                f"NIDS ALERT\n"
                f"Time: {timestamp}\n"
                f"Attack Type: {label}\n"
                f"Confidence: {confidence:.2f}%\n"
                f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
                f"Protocol: {protocol}"                                          
            )

            self.sns.publish(
                TopicArn = self.topic_arn,
                Message = message,
                Subject = f"NIDS Alert: {label} detected"
            )

            print(f"Alert sent successfully for {label} with {confidence:.2f}% confidence.")
            return True
        
        except Exception as e:
            print(f"Error occurred while sending alert: {e}")
            return False