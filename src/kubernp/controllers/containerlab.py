"""ContainerLab controller."""

import glob
from pathlib import Path
import yaml
import tempfile
import uuid
import copy

from kubernp.utils import recursive_merge

TOPO_VIEW_DEPLOYMENT="""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: topo-viewer-clab-%CLAB_UUID%
  labels:
    app: topo-viewer-clab-%CLAB_UUID%
spec:
  replicas: 1
  selector:
    matchLabels:
      app: topo-viewer-clab-%CLAB_UUID%
  template:
    metadata:
      name: topo-viewer-clab-%CLAB_UUID%
      labels:
        app: topo-viewer-clab-%CLAB_UUID%
        hackinsdn/displayName: topology-visualizer
    spec:
      containers:
      - name: topology-visualizer
        image: ghcr.io/srl-labs/clabernetes/clabernetes-launcher:latest
        ports:
        - containerPort: 50080
        command: ["sh", "-c"]
        args:
        - |
          service docker start
          echo Waiting for Docker daemon to be ready...
          until [ -S /var/run/docker.sock ]; do sleep 1; done
          service docker status
          docker info
          echo Waiting for topology to be ready...
          until [ -s /topology-data.yaml ]; do sleep 1; done
          cat /topology-data.yaml
          echo Starting clab graph...
          clab graph --offline --topo /topology-data.yaml
        volumeMounts:
        - name: clab-topology-data
          mountPath: /topology-data.yaml
          readOnly: true
          subPath: topology-data.yaml
        securityContext:
          privileged: true
      volumes:
      - name: clab-topology-data
        configMap:
          defaultMode: 0640
          name: topology-data-clab-%CLAB_UUID%
"""
TOPO_VIEW_SERVICE="""
apiVersion: v1
kind: Service
metadata:
  name: topo-viewer-clab-%CLAB_UUID%
  labels:
    app: topo-viewer-clab-%CLAB_UUID%
spec:
  type: NodePort
  ports:
  - port: 50080
    targetPort: 50080
    name: http-topology-visualizer
  selector:
    app: topo-viewer-clab-%CLAB_UUID%
"""


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
        self.log = self.kubernp.log

    def filename_from_uploads(self, filename, clab_files):
        """Try to get the correct filename from clab files."""
        for file in clab_files:
            if filename.endswith(f"/{file}"):
                return file
        return filename

    def parse_topology(self, topo_file, clab_name):
        """
        Process ContainerLab topology before running clabverter.

        As part of the processing phase, we execute the following steps:
        - Change topology name to avoid invalid characters (it will become subdomain in Kubernetes)
        - Handling absolute paths for startup-config and binds
        - Rename the topology file into clab_uuid to guarantee uniqueness
        """
        try:
            with open(topo_file, 'r') as f:
                topology = yaml.safe_load(f)
            assert "topology" in topology
            assert len(topology["topology"]["nodes"]) > 0
        except Exception as exc:
            raise Exception(f"Failed to load ContainerLab topology: {exc}")

        # Change topology name to avoid invalid characters
        topology["name"] = clab_name

        # Unroll nodes configs
        topology["topology"]["nodes"] = self.unroll_nodes_config(
            topology["topology"]["nodes"],
            topology["topology"].pop("defaults", {}),
            topology["topology"].pop("kinds", {}),
        )

        # Handle absolute paths
        clab_files = glob.glob("**/*", recursive=True, root_dir=topo_file.parent)
        for node_name, node in topology["topology"]["nodes"].items():
            # startup-config
            if node.get("startup-config"):
                node["startup-config"] = self.filename_from_uploads(node["startup-config"], clab_files)
            # binds
            for i, bind in enumerate(node.get("binds", [])):
                bind_opts = bind.split(":")
                filename = self.filename_from_uploads(bind_opts[0], clab_files)
                if bind_opts[0] == filename:
                    continue
                if len(bind_opts) == 1:
                    # in case we only have one filename, the mount point should be preserved
                    bind_opts.append(bind_opts[0])
                bind_opts[0] = filename
                node["binds"][i] = ":".join(bind_opts)

        return topology

    def get_topology_visualizer(self, clab_uuid, topology):
        """
        Create additional Kubernetes resources for Containerlab topology
        visualization.
        """
        docs = []
        docs.append(yaml.safe_load(TOPO_VIEW_DEPLOYMENT.replace("%CLAB_UUID%", clab_uuid)))
        docs.append(yaml.safe_load(TOPO_VIEW_SERVICE.replace("%CLAB_UUID%", clab_uuid)))
        docs.append({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": f"topology-data-clab-{clab_uuid}"},
            "data": {
                "topology-data.yaml": yaml.dump(topology),
            },
        })
        return docs

    def clean_up_for_topology_visualizer(self, topology):
        """We leverage 'clab graph' for topology visualization and it will fail
        with 'no such file or directory' error if binds are defined but files
        are not present. To avoid having to also mount files, we just remove
        binds.
        """
        if "defaults" in topology["topology"]:
            topology["topology"]["defaults"].pop("binds", None)
        for kind in topology["topology"].get("kinds", {}).values():
            kind.pop("binds", None)
        for group in topology["topology"].get("groups", {}).values():
            group.pop("binds", None)
        for node in topology["topology"]["nodes"].values():
            node.pop("binds", None)
        return topology

    def unroll_nodes_config(self, nodes, defaults, kinds):
        """
        In Containerlab, the configuration merging logic follows a specific
        hierarchy. To determine the final state of a node, the system starts
        with global defaults and overlays more specific layers until it reaches
        the individual node configuration.

        Precedence Order: Node > Kind > Defaults. If a setting exists in all
        three, the Node value is what gets applied to the container.

        Critical Note on List Merging: unlike dictionaries (like env or
        labels), Containerlab treats lists (like binds or ports) slightly
        differently depending on the version and configuration. Standard
        Behavior: Node-specific lists usually append to or overlay the
        kind-level lists.
        """
        final_configs = {}

        for node_name, node_cfg in nodes.items():
            # Start with a fresh deep copy of Global Defaults
            result = copy.deepcopy(defaults)

            # 1. Merge Kind-specific settings
            node_kind = node_cfg.get("kind") or defaults.get("kind")
            if node_kind in kinds:
                result = recursive_merge(result, kinds[node_kind], merge_list=True)

            # 2. Merge Node-specific settings (Highest Precedence)
            result = recursive_merge(result, node_cfg, merge_list=True)

            final_configs[node_name] = result

        return final_configs

    def is_containerlab(self, filename):
        """
        Apply some heuristics and validations to try to identify if the request
        is for a ContainerLab scenario.
        """
        return filename.endswith(".clab.yaml") or filename.endswith(".clab.yml")

    def prepare_lab(self, filename, **kwargs):
        """
        Parse the objects and prepare some configuration to run the
        ContainerLab experiment. Content must be YAML encoded string.
        """
        # TODO: handle imagePullSecrets
        # TODO: run clabverter
        # TODO: all other stuff we do on Dashboard HackInSDN
        #
        pod_hash = uuid.uuid4().hex[:10]
        clab_name = f"clab-{pod_hash}"
        resources = []

        topo_file = Path(filename).expanduser()
        topo_dirname = topo_file.parent.name
        self.log.info(f"- Containerlab - parsing topology...")
        topology = self.parse_topology(topo_file, clab_name)

        self.log.info(f"- Containerlab - starting clabverter Pod...")
        tmp_exp = self.kubernp.create_experiment()
        if not tmp_exp.uid:
            return
        clabverter = tmp_exp.create_pod(
            name=f"clabverter-{pod_hash}",
            image="hackinsdn/clabverter:latest",
            command=["sleep"], args=["infinity"],
        )
        status, msg = clabverter.wait_running()
        if not status:
            self.log.error(f"Error waiting for clabverter to be running: {msg}")
            self.kubernp.delete_experiment(tmp_exp)
            return
        self.log.info(f"- Containerlab - uploading files to clabverter...")
        clabverter.upload_files(topo_file.parent, quiet=True)

        with tempfile.NamedTemporaryFile() as tmp:
            with open(tmp.name, "w") as f:
                yaml.dump(topology, f)
            clabverter.upload_files(tmp.name, quiet=True)
            output = clabverter.exec(f"mv /uploads/{Path(tmp.name).name} /uploads/{topo_dirname}/{clab_name}.clab.yaml")
            if output != "":
                self.log.error(f"Error uploading containerlab topology file: {output}")
                self.kubernp.delete_experiment(tmp_exp)
                return

        output = clabverter.exec(f"unlink /uploads/{topo_dirname}/{topo_file.name}")
        if output != "":
            self.log.error(f"Error removing previous containerlab topology file: {output}")
            self.kubernp.delete_experiment(tmp_exp)
            return

        self.log.info(f"- Containerlab - running clabverter...")
        result = clabverter.exec(
            f"cd /uploads/{topo_dirname} && "
            f"clabverter --stdout --quiet --destinationNamespace {self.kubernp.k8s.namespace}"
        )

        has_error = False
        for doc in result.split("---\n"):
            try:
                yaml_doc = yaml.safe_load(doc)
            except:
                has_error = True
                break
            if not yaml_doc:
                continue
            if yaml_doc.get("kind") == "Namespace":
                continue
            resources.append(yaml_doc)
        if not resources or has_error:
            self.log.error(f"Convert ContainerLab failed: {result}")
            self.kubernp.delete_experiment(tmp_exp)
            return

        self.log.info(f"- Containerlab - Removing clabverter Pod no longer needed")
        self.kubernp.delete_experiment(tmp_exp)

        self.log.info(f"- Containerlab - Adding resources for topology visualizer")
        topology = self.clean_up_for_topology_visualizer(topology)
        resources.extend(self.get_topology_visualizer(pod_hash, topology))

        self.log.info(f"- Containerlab - lab converted successfully!")

        return resources
