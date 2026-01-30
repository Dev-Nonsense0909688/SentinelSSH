import re
from abc import ABC, abstractmethod

class AttackRule(ABC):
    name: str
    threat_level: str
    pattern: re.Pattern

    def match(self, line: str):
        return self.pattern.search(line)

    @abstractmethod
    def build_event(self, match, timestamp, line):
        pass



class PrivilegedAccountBruteforce(AttackRule):
    def __init__(self):
        self.name = "privileged_acc_bruteforce"
        self.threat_level = "critical"
        self.pattern = re.compile(
            r'Failed password for root from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2'
        )

    def build_event(self, match, timestamp, line):
        return {
            "timestamp": timestamp,
            "attack_type": self.name,
            "threat_level": self.threat_level,
            "ip": match.group("ip"),
            "port": match.group("port"),
            "line": line
        }

class UsernameEnumeration(AttackRule):
    def __init__(self):
        self.name = "username_enumeration"
        self.threat_level = "medium"
        self.pattern = re.compile(
            r'Invalid user (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        )

    def build_event(self, match, timestamp, line):
        return {
            "timestamp": timestamp,
            "attack_type": self.name,
            "threat_level": self.threat_level,
            "user": match.group("user"),
            "ip": match.group("ip"),
            "line": line
        }

class SSHBruteforce(AttackRule):
    def __init__(self):
        self.name = "ssh_bruteforce"
        self.threat_level = "high"
        self.pattern = re.compile(
            r'Failed password for invalid user (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2'
        )

    def build_event(self, match, timestamp, line):
        return {
            "timestamp": timestamp,
            "attack_type": self.name,
            "threat_level": self.threat_level,
            "user": match.group("user"),
            "ip": match.group("ip"),
            "port": match.group("port"),
            "line": line
        }

class AutomatedBruteforce(AttackRule):
    def __init__(self):
        self.name = "automated_bruteforce"
        self.threat_level = "high"
        self.pattern = re.compile(
            r'reverse mapping checking getaddrinfo for (?P<host>[\w\.-]+) '
            r'\[(?P<ip>\d+\.\d+\.\d+\.\d+)\] failed - POSSIBLE BREAK-IN ATTEMPT!'
        )

    def build_event(self, match, timestamp, line):
        return {
            "timestamp": timestamp,
            "attack_type": self.name,
            "threat_level": self.threat_level,
            "host": match.group("host"),
            "ip": match.group("ip"),
            "line": line
        }
