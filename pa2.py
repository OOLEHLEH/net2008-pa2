# Name: Roberto Mestizo Slane
# Student ID: 041268024

import xml.etree.ElementTree as ET
import yaml
import itertools
import json
import sys


def main():
    """Run the fleet compliance audit."""
    if len(sys.argv) != 3:
        print("Usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    xml_filename = sys.argv[1]
    yaml_filename = sys.argv[2]

    try:
        root = load_inventory(xml_filename)
    except FileNotFoundError:
        print(f"Error: File not found: {xml_filename}")
        sys.exit(1)
    except ET.ParseError:
        print(f"Error: Invalid XML file: {xml_filename}")
        sys.exit(1)

    site = root.get("site")

    try:
        policy = load_policy(yaml_filename)
    except FileNotFoundError:
        print(f"Error: File not found: {yaml_filename}")
        sys.exit(1)
    except yaml.YAMLError:
        print(f"Error: Invalid YAML file: {yaml_filename}")
        sys.exit(1)
    except PolicyError as error:
        print(f"Error: {error}: {yaml_filename}")
        sys.exit(1)

    devices = root.findall("device")
    skipped_devices = 0
    roles = {}

    interfaces = {
        "up": 0,
        "down": 0,
        "other": 0
    }

    violations = []
    compliant = []

    for device in devices:
        device_obj = Device(device)
        device_id = device_obj.get_id()

        if device_id is None:
            skipped_devices += 1
            continue

        role = device_obj.get_role()
        os_version = device_obj.get_os()
        owner = device_obj.get_owner()

        if policy.get("require_owner", False) and not owner:
            violations.append({
                "device": device_id,
                "type": "missing_owner"
            })

        if "min_os" in policy:
            min_os = policy["min_os"]
            required_version = min_os.get(role)

            if required_version is None:
                violations.append({
                    "device": device_id,
                    "type": "unknown_role",
                    "role": role
                })
            elif version_is_older(os_version, required_version):
                violations.append({
                    "device": device_id,
                    "type": "os_outdated",
                    "found": os_version,
                    "required": required_version
                })

        roles[role] = roles.get(role, 0) + 1
        down_count = 0

        for interface in device_obj.get_interfaces():
            status = interface.get("status")

            if status == "up":
                interfaces["up"] += 1
            elif status == "down":
                interfaces["down"] += 1
                down_count += 1
            else:
                interfaces["other"] += 1

        max_down = policy.get("max_down_interfaces")

        if max_down is not None and down_count > max_down:
            violations.append({
                "device": device_id,
                "type": "too_many_down",
                "down": down_count
            })

        if not any(v["device"] == device_id for v in violations):
            compliant.append(device_id)
    
    total_devices = len(devices) - skipped_devices

    report = {
        "site": site,
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant)
    }

    with open("audit.json", "w") as file:
        json.dump(report, file, indent=4)

    print("Audit report saved to audit.json")
    print("Total devices:", total_devices)
    print("Skipped devices:", skipped_devices)
    print("Roles:", roles)
    print("Interfaces:", interfaces)
    print("Violations:", violations)
    print("Compliant devices:", sorted(compliant))


def version_is_older(found, required):
    """Return True if the found version is older than the required version."""
    found_parts = [int(part) for part in found.split(".")]
    required_parts = [int(part) for part in required.split(".")]

    for found_part, required_part in itertools.zip_longest(
        found_parts, required_parts, fillvalue=0
    ):
        if found_part < required_part:
            return True
        if found_part > required_part:
            return False

    return False


class Device:
    """Represent a network device from the XML inventory."""

    def __init__(self, element):
        """Store the XML element for this device."""
        self.element = element

    def get_id(self):
        """Return the device ID."""
        return self.element.get("id")

    def get_role(self):
        """Return the device role."""
        return self.element.get("role")

    def get_os(self):
        """Return the device operating system version."""
        return self.element.get("os")

    def get_owner(self):
        """Return the device owner, removing surrounding whitespace."""
        owner = self.element.findtext("owner")
        return owner.strip() if owner else None

    def get_interfaces(self):
        """Return the device interfaces."""
        return self.element.findall("interface")


class PolicyError(Exception):
    """Represent an error in the policy file."""


def load_policy(filename):
    """Load and validate the YAML policy file."""
    with open(filename, "r") as file:
        policy = yaml.safe_load(file)

    if policy is None:
        policy = {}
    elif not isinstance(policy, dict):
        raise PolicyError("Policy must be a YAML mapping")

    return policy


def load_inventory(filename):
    """Load the XML device inventory."""
    tree = ET.parse(filename)
    return tree.getroot()


if __name__ == "__main__":
    main()
