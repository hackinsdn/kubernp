"""KubeRNP utils."""

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


def recursive_merge(dict1, dict2):
    """
    Recursively merges dict2 into dict1.

    For conflicts:
    - If both values are dictionaries, they are merged recursively.
    - Otherwise, the value from dict2 overwrites the value from dict1.
    """
    merged = dict1.copy()
    for key, value in dict2.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            # If both key values are dicts, merge them recursively
            merged[key] = recursive_merge(merged[key], value)
        else:
            # Otherwise, overwrite the value in dict1 with the value from dict2
            merged[key] = value
            
    return merged
