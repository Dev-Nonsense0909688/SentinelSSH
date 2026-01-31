import re
from abc import ABC, abstractmethod

class AttackRule(ABC):
    name: str
    threat_level: str
    pattern: re.Pattern
    reason: str
    severity_score: int
    
    def match(self, line: str):
        return self.pattern.search(line)

    @abstractmethod
    def build_event(self, match, timestamp, line):
        pass



class PrivilegedAccountBruteforce(AttackRule):
    def __init__(self):
        self.name = "privileged_acc_bruteforce"
        self.threat_level = "critical"
        self.severity_score = 5
        self.reason = "Privileged account (root) brute-force detected ({count} attempts)"
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
        self.severity_score = 1
        self.reason = "Username enumeration activity ({count} attempts)"
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
        self.reason = "SSH brute-force attempts detected ({count} attempts)"
        self.severity_score = 2
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
        self.severity_score = 3 
        self.reason = "Automated brute-force detected ({count} attempts)"
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

def load_map():
    result = {}
    for cls in AttackRule.__subclasses__():
        result[cls().name] = cls().reason
    return result

def load_names():
    result = []
    for cls in AttackRule.__subclasses__():
        result.append(cls().name)
    
    return result

def load_severity():
    result = {}
    for cls in AttackRule.__subclasses__():
        result[cls().name] = cls().severity_score
        
    return result