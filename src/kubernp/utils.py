"""KubeRNP utils."""

import datetime
import re

K8S_NAME_RE = re.compile(
    r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
)


def validate_k8s_name(name):
    """
    Validate Kubernetes names, to be used as metadata.name

    Kubernetes names (metadata.name) are lowercase RFC 1123 subdomain and must
    consist of lower case alphanumeric characters, '-' or '.', and must start
    and end with an alphanumeric character.
    """
    if not K8S_NAME_RE.match(name):
        raise ValueError(
            f"Invalid kubernetes name '{name}', must be a valid RFC 1123 subdomain"
        )
    return name


def recursive_merge(dict1, dict2, merge_list=False):
    """
    Recursively merges dict2 into dict1.

    For conflicts:
    - If both values are dictionaries, they are merged recursively.
    - For Lists: Appended together (to handle binds/ports).
    - Otherwise, the value from dict2 overwrites the value from dict1.
    """
    for key, value in dict2.items():
        if key in dict1 and isinstance(dict1[key], dict) and isinstance(value, dict):
            # If both key values are dicts, merge them recursively
            recursive_merge(dict1[key], value, merge_list=merge_list)
        elif merge_list and isinstance(value, list) and key in dict1 and isinstance(dict1[key], list):
            # Merge lists (e.g., combining kind binds with node binds)
            dict1[key] = dict1[key] + [item for item in value if item not in dict1[key]]
        else:
            # Otherwise, overwrite the value in dict1 with the value from dict2
            dict1[key] = value

    return dict1


def format_duration(input_date) -> str:
    """
    Enhanced timedelta format duration from kubernetes.utils.duration
    """
    delta = None
    if isinstance(input_date, datetime.timedelta):
        delta = input_date
    elif isinstance(input_date, datetime.datetime):
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        delta = now - input_date
    elif isinstance(input_date, str):
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        delta = now - datetime.datetime.fromisoformat(input_date)

    # Sanity check: short-circuit if we have a zero delta or early range
    if delta is None or delta <= datetime.timedelta(0):
        return "--"

    # After that, do the usual div & mod tree to take seconds and get days
    # hours, minutes, and seconds from it.
    secs = int(delta.total_seconds())

    output: List[str] = []

    if delta.days >= 2:
        output.append(f"{delta.days}d")
        if delta.days > 6:
            secs = 0
        else:
            secs -= delta.days * 86400

    hours = secs // 3600
    if hours > 0:
        output.append(f"{hours}h")
        if delta.days > 1 or hours > 3:
            secs = 0
        else:
            secs -= hours * 3600

    minutes = secs // 60
    if minutes > 0:
        output.append(f"{minutes}m")
        if minutes > 4:
            secs = 0
        else:
            secs -= minutes * 60

    if secs > 0:
        output.append(f"{secs}s")

    return "".join(output)
