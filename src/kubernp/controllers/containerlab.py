"""ContainerLab controller."""

class ContainerlabController:
    """
    ContainerLab Controller: helper class with specific heuristics to identify
    a manifest with Mininet-Sec resources and prepare the manifest accordingly.
    """

    def __init__(self, kubernp):
        """
        Initialize ContainerLab Controller
        """
        self.kubernp = kubernp
        self.k8s = self.kubernp.k8s

    def is_containerlab(self, filename):
        """
        Apply some heuristics and validations to try to identify if the request
        is for a ContainerLab scenario.
        """
        return False

    def prepare_lab(self, filename, **kwargs):
        """
        Parse the objects and prepare some configuration to run the
        ContainerLab experiment. Content must be YAML encoded string.
        """
        pod_hash = uuid.uuid4().hex[:10]
        resources = []
        # TODO: run claberverter
        # TODO: all other stuff we do on Dashboard HackInSDN
        return resources, f"{clab}-{pod_hash}"
