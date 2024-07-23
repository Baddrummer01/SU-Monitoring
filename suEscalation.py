#!/usr/bin/python3
import pwd
import re
import subprocess
import sys
import time
import logging

LOG_FILE = "/var/log/auth.log"
DATA_STORAGE = "/var/log/su_monitor.log"
FAILURE_THRESHOLD = 3 # number of attempts until usermod -L
CHECK_INTERVAL = 5  # seconds

# Dictionary to track su attempts
su_attempts = {}

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.FileHandler(filename=DATA_STORAGE, mode="w"), #log in write mode
                        logging.StreamHandler(sys.stdout)
                    ])


# monitors su attempts. Processes the su function after the monitor to figure out what to do with it
# uses /var/log/auth.log
def monitorLog():
    # list to exclude already processed entries
    su_lines = []
    initial_execution = True
    while True:
        with open(LOG_FILE, "r") as log:
            for line in log:
                # this "if" is checking if there's a su in the command line to record it
                if "su:" not in line:
                    continue
                try:
                    if line in su_lines:
                        continue
                    else:
                        su_lines.append(line)
                        if not initial_execution:
                            processLine(line)
                except IndexError:
                    # IndexError could occur with an empty file
                    break
            initial_execution = False
            time.sleep(CHECK_INTERVAL)


# Filters lines only by failed attempts and opened sessions, uses regex to get timestamp, target user and calling user.
def processLine(line):
    """
    :param line: str: line from auth.log passed by monitorLog function
    """
    if "failed".casefold() in line.casefold():
        match = re.search(r"(\w{3} \d+ \d+:\d+:\d+) \S+ su: FAILED SU [(]to (\S+)[)] (\S+)", line)
        if match:
            timestamp, target_user, user = match.groups()
            handleFail(user, target_user, timestamp)
    elif "session opened for user".casefold() in line.casefold():
        match = re.search(
            r"(\w{3} \d+ \d+:\d+:\d+) \S+ su: pam_unix[(]su:session[)]: session opened for user (\S+)[(]uid=\d+[)] by [(]uid=(\d+)[)]", line)
        if match:
            timestamp, target_user, user = match.groups()
            user = pwd.getpwuid(int(user)).pw_name
            handleSuccess(user, target_user, timestamp)


# Add user and target_user to dictionary or increase failure count, suspend user if failure count exceeds limit.
def handleFail(user, target_user, timestamp):
    """
    :param user: user calling su, passed by processLine
    :param target_user: su target, passed by processLine
    :param timestamp: timestamp of su attempt, passed by processLine
    """
    key = (user, target_user)
    if key not in su_attempts:
        su_attempts[key] = {"failures": 0, "last_success": None}
    su_attempts[key]["failures"] += 1

    logging.info(
        f"\nFailed su attempt:\n user={user} \n target={target_user} \n time={timestamp} \n failures={su_attempts[key]['failures']}\n")

    if su_attempts[key]["failures"] >= FAILURE_THRESHOLD:
        suspendUser(user)
        # this puts the failures back at 0
        # if the account is unsuspended and the program is rerun, the user will not get rebanned instantly
        su_attempts[key]["failures"] = 0
        pass


# this function resets the failure count on a success when running su
def handleSuccess(user, target_user, timestamp):
    """
    :param user: user calling su, passed by processLine
    :param target_user: su target, passed by processLine
    :param timestamp: timestamp of su attempt, passed by processLine
    """
    key = (user, target_user)
    if key in su_attempts:
        su_attempts[key]["failures"] = 0
    su_attempts[key] = {"failures": 0, "last_success": timestamp}
    logging.info(f"Logging commands for user {target_user}\n")

    logging.info(f"\nSuccessful su attempt:\n user={user} \n target={target_user} \n time={timestamp}\n")


# this function runs usermod -L after too many failed attempts. USE WITH CAUTION
# restore functionality with sudo usermod -U {username}
def suspendUser(user):
    try:
        subprocess.run(["usermod", "-L", user], check=True)
        logging.info(f"\nAccount {user} has been suspended due to too many failed su attempts!!!\n Contact your administrator.\n")
        logging.info(f"\nRunning sudo pkill -KILL -u {user}\n")
        subprocess.run(["sudo", "pkill", "-KILL", "-u", user], check=True)
        logging.info(f"\nPkill successful for user {user}\n")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to suspend account {user}: {e}")

if __name__ == "__main__":
    logging.info("Starting su monitor script")
    monitorLog()
