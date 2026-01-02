"""Mininet-Sec controller."""

import uuid
import os
import base64

import yaml

class MininetSecController:
    """
    Mininet-Sec Controller: helper class with specific heuristics to identify
    a manifest with Mininet-Sec resources and prepare the manifest accordingly.
    """

    def __init__(self, kubernp):
        """
        Initialize Mininet-Sec Controller
        """
        self.kubernp = kubernp
        self.k8s = self.kubernp.k8s
        self.log = self.kubernp.log

    def create_kubeconfig_secret(self, name, kubeconfig):
        """
        Create kubeconfig Secret manifest to included into Mininet-sec
        """
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                },
            },
            "type": "Opaque",
        }

        with open(os.path.expanduser(kubeconfig), 'rb') as f:
            secret["data"] = {
                "kubeconfig": base64.b64encode(f.read()).decode('utf-8')
            }

        return secret

    def update_deployment_volume(self, deployment, sec_name):
        """
        Update Deployment spec to include a Secret as Volume into the first
        container. Additionally, remove the volume "mnsec-proxy-ca-configmap"
        which is commonly used for Mininet-Sec Proxy.
        """
        vol_name = "vol-" + sec_name
        volume = {
            "name": vol_name,
            "secret": {"secretName": sec_name},
        }
        volume_mount = {
            "name": vol_name,
            "mountPath": "/root/.kube/config",
            "subPath": "kubeconfig",
            "readOnly": True,
        }
        if not deployment["spec"]["template"]["spec"].get("volumes"):
            deployment["spec"]["template"]["spec"]["volumes"] = []
        deployment["spec"]["template"]["spec"]["volumes"].append(volume)
        if not deployment["spec"]["template"]["spec"]["containers"][0].get("volumeMounts"):
            deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = []
        deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append(volume_mount)

        # Remove mnsec-proxy-ca-configmap used with mnsec-proxy
        idx = -1
        vol_mount_name = ""
        for i, volume in enumerate(deployment["spec"]["template"]["spec"]["volumes"]):
            if volume.get("configMap", {}).get("name") == "mnsec-proxy-ca-configmap":
                vol_mount_name = volume["name"]
                idx = i
                break
        if idx != -1:
            del deployment["spec"]["template"]["spec"]["volumes"][idx]
        idx = -1
        for i, vol_mount in enumerate(deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]):
            if vol_mount.get("name") == vol_mount_name:
                idx = i
                break
        if idx != -1:
            del deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][idx]

    def is_mininetsec(self, content, **kwargs):
        """
        Apply some heuristics and validations to try to identify if the request
        is for a Mininet-Sec/HackInSDN scenario.

        Additional paramters:
        :param mnsec_image: docker image used for Mininet-Sec (defaults to
            hackinsdn/mininet-sec)
        """
        try:
            resources = yaml.safe_load_all(content)
        except:
            return False
        mnsec_image = kwargs.get("mnsec_image", "hackinsdn/mininet-sec")
        for doc in resources:
            if doc.get("kind") == "Deployment" and mnsec_image in doc["spec"]["template"]["spec"]["containers"][0]["image"]:
                return True
        return False

    def prepare_lab(self, content, **kwargs):
        """
        Parse the objects and prepare some configuration to run the
        Mininet-Sec/HackInSDN Lab. Content must be YAML encoded string.

        Additional paramters:
        :param mnsec_image: docker image used for Mininet-Sec (defaults to
            hackinsdn/mininet-sec)
        """
        self.log.info(" - Mininet-Sec: replate token strings...")
        mnsec_image = kwargs.get("mnsec_image", "hackinsdn/mininet-sec")
        pod_hash = uuid.uuid4().hex[:10]
        content = content.replace("${pod_hash}", pod_hash)

        self.k8s.update_nodes()
        allowed_nodes = [name for name, info in self.k8s.node_info.items() if "worker" in info["roles"]]
        content = content.replace("${allowed_nodes}", str(allowed_nodes))
        content = content.replace("${allowed_nodes_str}", ",".join(allowed_nodes))

        self.log.info(" - Mininet-Sec: loading resources and adding kubeconfig secret...")
        docs = []
        # create kubeconfig as a secret for Mininet-Sec to allow creating pods
        sec_name = f"sec-kubeconfig-{pod_hash}"
        docs.append(self.create_kubeconfig_secret(sec_name, self.k8s.kubeconfig))
        for doc in yaml.safe_load_all(content):
            # inject the kubeconfig as a volume and volume mount on mininet-sec deployment
            if doc.get("kind") == "Deployment" and mnsec_image in doc["spec"]["template"]["spec"]["containers"][0]["image"]:
                self.update_deployment_volume(doc, sec_name)
            docs.append(doc)

        self.log.info(" - Mininet-Sec: all done!")
        return docs
