"""KubeRNP Experiment"""

import uuid
import re
import logging
import json
import traceback
import os
import tarfile
import tempfile
import time
import base64
from pathlib import Path
from typing import Optional

from kubernetes.client.exceptions import ApiException

from kubernp.utils import recursive_merge, validate_k8s_name, format_duration
from kubernp.output import show_table
from kubernetes.stream import stream
from kubernp.certutils import generate_selfsigned_cert

def create_tar(source_path: Path, tar_path: Path) -> None:
    """Create a tar archive from a file or directory."""
    with tarfile.open(tar_path, "w") as tar:
        tar.add(source_path.expanduser(), arcname=source_path.name)


class Resource:
    """Abstract and encapsulate an Resource for Experiment."""

    def __init__(self, experiment, name, kind, api_version, k8s_dict):
        self.experiment = experiment
        self.name = name
        self.kind = kind
        self.api_version = api_version
        self.k8s_dict = k8s_dict

        self.shell = None
        self.log = self.experiment.log
        self.pod_name = None
        self.container_name = None

    def get_k8s(self):
        """Obtain K8s object."""
        return self.experiment.k8s.get_resource(self.api_version, self.kind, self.name)

    def update_k8s(self, body):
        """Update Kubernetes resource (patch)."""
        resp = self.experiment.k8s.update_resource(self.api_version, self.kind, self.name, body)
        self.k8s_dict = resp.to_dict()

    def get_k8s_pods(self):
        if self.kind == "Pod":
            return [self.k8s_dict]
        if self.kind == "Deployment":
            try:
                pods = self.experiment.k8s.get_resource(
                    "v1", "Pod", None, label_selector=f"app={self.name}"
                ).items
            except:
                self.log.error(f"Failed to obtain container for {self.kind}/{name}")
                return None
            return [pod.to_dict() for pod in pods]
        return None

    def exec(self, cmd, pod_name=None):
        pod_name = self.get_pod_name(pod_name)
        if not pod_name:
            self.log.error(f"Resource {self.kind}/{self.name} does not support exec")
            return

        cmd = " ".join(cmd) if isinstance(cmd, list) else cmd
        if cmd[-1] == "&":
            cmd = cmd[:-1] + ">/dev/null 2>&1 & echo $!"
        cmd = ["/bin/sh", "-c", cmd]
        resp = stream(
            self.experiment.k8s.v1_api.connect_get_namespaced_pod_exec,
            name=pod_name,
            namespace=self.experiment.k8s.namespace,
            container=self.name,
            command=cmd,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        return resp

    def list_pods(self):
        pods = self.get_k8s_pods()
        if not pods:
            print(f"No Pods found for this resource ({self.kind}/{self.name})")
            return
        pods_table = {"NAME": [], "STATUS": [], "AGE": []}
        for pod in pods:
            pods_table["NAME"].append(pod["metadata"]["name"])
            pods_table["AGE"].append(format_duration(pod["metadata"]["creationTimestamp"]))
            pods_table["STATUS"].append(pod["status"]["phase"])

        return show_table(pods_table, output=self.experiment.kubernp.output)

    def get_pod_name(self, pod_name=None):
        """Get pod name from a deployment or filter the existing ones."""
        pods = self.get_k8s_pods()
        if not pods:
            return None
        if len(pods) > 1:
            if not pod_name:
                self.log.error(f"Multiple Pods found, please provide the 'pod_name'. Use the list_pods() function.")
                return None
            names = set([pod["metadata"]["name"] for pod in pods])
            if pod_name not in names:
                self.log.error(f"The provided 'pod_name' was not found.")
                return None
        else:
            pod_name = pods[0]["metadata"]["name"]
        return pod_name

    def publish(self, port, type="NodePort"):
        self.experiment.create_service(f"srv-{self.name}-{type.lower()}-{port}", srv_type=type, ports=[port], selector={"app": self.name}, labels={"app": self.name})

    def get_endpoints(self):
        pods = self.get_k8s_pods()
        if not pods:
            self.log.error(f"Resource {kind}/{name} does not support endpoints")
            return
        try:
            services = self.experiment.k8s.get_resource(
                "v1", "Service", None, label_selector=f"app={self.name}"
            ).items
        except:
            services = []
        endpoints = {}
        for srv in services:
            for port in srv.spec.ports:
                port_name = port.name or f"{port.port}-{port.protocol.lower()}"
                endpoints[port_name] = []
                for pod in pods:
                    node_ip = self.experiment.k8s.get_node_ip(pod["spec"]["nodeName"])
                    if node_ip and ":" in node_ip:
                        node_ip = f"[{node_ip}]"
                    if port.nodePort:
                        endpoints[port_name].append(f"{node_ip}:{port.nodePort}")
        return endpoints

    def upload_files(self, local_path, pod_name=None, chunk_size=1024*1024):
        pod_name = self.get_pod_name(pod_name)
        if not pod_name:
            self.log.error(f"Resource {self.kind}/{self.name} does not support uploads")
            return

        with tempfile.NamedTemporaryFile() as tmp:
            create_tar(Path(local_path), Path(tmp.name))
            total_size = os.path.getsize(tmp.name)

            exec_command = ["tar", "xvf", "-", "-C", "/uploads"]

            resp = stream(
                self.experiment.k8s.v1_api.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=self.experiment.k8s.namespace,
                container="upload-mgmt-sidecar",
                command=exec_command,
                stderr=True,
                stdin=True,
                stdout=True,
                tty=False,
                _preload_content=False,
            )

            sent = 0
            start_time = time.time()

            with open(tmp.name, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    resp.write_stdin(chunk)
                    sent += len(chunk)

                    elapsed = time.time() - start_time
                    percent = (sent / total_size) * 100
                    speed = sent / elapsed if elapsed > 0 else 0

                    print(
                        f"\rUploading: {percent:6.2f}% "
                        f"({sent / (1024**2):.2f} MB / "
                        f"{total_size / (1024**2):.2f} MB) "
                        f"@ {speed / (1024**2):.2f} MB/s",
                        end="",
                        flush=True,
                    )

            resp.close()
            print("\nUpload completed! Saved to /uploads")

    def scale(self, replica_count):
        """
        Scales a Kubernetes deployment to the specified replica count.
        """
        if self.kind != "Deployment":
            self.log.error(f"Resource {self.kind}/{self.name} does not support scale")
            return
        body = {"spec": {"replicas": replica_count}}
        try:
            resp = self.experiment.k8s.apps_v1_api.patch_namespaced_deployment_scale(
                name=self.name,
                namespace=self.experiment.k8s.namespace,
                body=body
            )
        except Exception as exc:
            self.log.error(f"Failed to scale {self.kind}/{self.name}: {exc}")
            return
        print(f"Resource {self.kind}/{self.name} scaled to {resp.spec.replicas} replicas.")

    def attach_pvc(self, pvc_name, mount_path):
        """
        Updates an existing deployment to include a volume mount from a PVC.
        """
        if self.kind != "Deployment":
            self.log.error(f"Resource {self.kind}/{self.name} does not support attaching PVC.")
            return
        vol_name = "vol-" + uuid.uuid4().hex[:10]
        volume = {
            "name": vol_name,
            "persistentVolumeClaim": {"claimName": pvc_name},
        }
        volume_mount = {
            "name": vol_name,
            "mountPath": mount_path,
        }
        
        deployment = self.get_k8s_body()
        if not deployment:
            self.log.error(f"Deployment not found {self.kind}/{self.name}")
            return

        if deployment.spec.template.spec.volumes is None:
            deployment.spec.template.spec.volumes = []

        deployment.spec.template.spec.volumes.append(volume)

        container_found = False
        for container in deployment.spec.template.spec.containers:
            if container.name == self.name:
                if container.volumeMounts is None:
                    container.volumeMounts = []
                container.volumeMounts.append(volume_mount)
                container_found = True
                break
            
        if not container_found:
            self.log.error(f"Container '{self.name}' not found in deployment.")
            return

        self.update_k8s(deployment)

        print(f"Successfully attached {pvc_name} to {self.name} at {mount_path}")

    def publish_http(self, **attrs):
        """
        Create correspondent Service and Ingress resources to publish to allow
        external access to this deployment via HTTP and HTTPS traffic.

        See Experiment.create_ingress() for allowed attributes.
        """
        if not attrs.get("host"):
            self.log.error("Invalid parameter for publish_http - missing 'host' attribute. Skipping")
            return
        if not (service_port := attrs.get("service_port")):
            self.log.error("Invalid parameter for publish_http - missing 'service_port' attribute. Skipping")
            return
        if not attrs.get("name"):
            attrs["name"] = f"{self.name}-{service_port}"
        attrs["create_service"] = True
        attrs["service_selector"] = {"app": self.name}
        try:
            res = self.experiment.create_ingress(**attrs)
            assert res
        except Exception as exc:
            self.log.error("Failed to create Ingress. Skipping")


class Experiment:
    """Abstract and encapsulate an Experiment with resources."""

    def __init__(self, kubernp, name="", load=False, skip_errors=False, description="", resources=[], default_image="alpine:latest", notifications=[], expiration="never"):
        """Create an Experiment."""
        self.kubernp = kubernp
        self.k8s = self.kubernp.k8s
        self.name = validate_k8s_name(name) if name else f"exp-{uuid.uuid4()}"
        self.description = description
        self.default_image = default_image
        self.notifications = []
        self.expiration = expiration

        self.k8s_dict = None
        self.resources = {}
        self.resource_names = {}
        self.log = logging.getLogger("kubernp")

        try:
            if load:
                self.load(skip_errors=skip_errors)
            else:
                self.save()
            self.uid = self.k8s_dict["metadata"]["uid"]
        except Exception as exc:
            action = "load" if load else "create"
            self.log.error(f"Failed to {action} Expirement: {exc}")
            return

        self.create_resources(resources)

    def save(self, apply=False):
        configmap = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": self.name,
                "labels": {
                    "kubernp/kind": "Experiment",
                },
            },
            "data": {
                "description": self.description,
                "notifications": json.dumps(self.notifications),
                "expiration": self.expiration,
                "resources": json.dumps(list(self.resources.keys())),
            },
        }
        result = self.k8s.create_from_dict(configmap, apply=apply)
        self.k8s_dict = result

    def load(self, skip_errors=False):
        try:
            result = self.k8s.get_resource("v1", "ConfigMap", self.name)
            k8s_exp = result.to_dict()
            assert "data" in k8s_exp
        except Exception as exc:
            err = traceback.format_exc().replace("\n", ", ")
            self.log.error(f"Failed to load Experiment: {exc} -- {err} -- {result}")
        self.description = k8s_exp["data"].get("description", "")
        self.notifications = json.loads(k8s_exp["data"].get("notifications", ""))
        self.expiration = k8s_exp["data"].get("expiration", "never")
        resources = json.loads(k8s_exp["data"].get("resources", "[]"))
        for keys in resources:
            error = None
            try:
                result = self.k8s.get_resource(*keys)
                self.resources[tuple(keys)] = {
                    "request": {},
                    "resource": Resource(
                        experiment=self,
                        name=keys[2],
                        kind=keys[1],
                        api_version=keys[0],
                        k8s_dict=result.to_dict(),
                    ),
                }
                self.resource_names[f"{keys[1]}/{keys[2]}"] = tuple(keys)
            except ApiException as api_exc:
                error = f"Failed to load Resource {keys}: reason={api_exc.reason}: {api_exc.body}"
            except Exception as exc:
                trace = traceback.format_exc().replace("\n", ", ")
                error = f"Failed to load Resource {keys}: {exc} -- {trace}"
            if error and not skip_errors:
                raise Exception(error + " -- (try again with skip_errors=True)")
        self.k8s_dict = k8s_exp

    def create_deployment(self, name, **kwargs):
        """
        Create a k8s deployment and optionally publish services.

        All attributes supported are documented in docs/API.md.
        image="", publish=[], publish_http=[], spec={}):
        """
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "spec": {
                "selector": {
                    "matchLabels": {"app": name},
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": name,
                            "kubernp/Experiment": self.name,
                        },
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": name,
                                "image": kwargs.get("image", self.default_image),
                                "ports": [],
                            },
                        ],
                    }
                }
            }
        }

        for port in kwargs.get("publish", []) + kwargs.get("ports", []):
            container_port = port
            if isinstance(port, dict):
                container_port = port.get("port")
            if not isinstance(container_port, int):
                self.log.error(f"Invalid port {port}")
                return
            deployment["spec"]["template"]["spec"]["containers"][0]["ports"].append(
                {"containerPort": container_port}
            )

        for attrs in kwargs.get("publish_http", []):
            if isinstance(attrs, dict) and attrs.get("service_port"):
                deployment["spec"]["template"]["spec"]["containers"][0]["ports"].append(
                    {"containerPort": attrs["service_port"]}
                )

        if "command" in kwargs:
            deployment["spec"]["template"]["spec"]["containers"][0]["command"] = kwargs["command"]

        if "args" in kwargs:
            deployment["spec"]["template"]["spec"]["containers"][0]["args"] = kwargs["args"]

        if "replicas" in kwargs:
            deployment["spec"]["replicas"] = kwargs["replicas"]

        if "node_affinity" in kwargs:
            deployment["spec"]["template"]["spec"]["affinity"] = {
                "nodeAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": {
                        "nodeSelectorTerms": [{
                            "matchExpressions": [{
                                "key": "kubernetes.io/hostname",
                                "operator": "In",
                                "values": kwargs["node_affinity"].split(","),
                            }],
                        }],
                    },
                },
            }

        if "pvc" in kwargs:
            pvc_name = kwargs["pvc"].pop("name")
            pvc_mount_path = kwargs["pvc"].pop("mount_path")
            pvc_sub_path = kwargs["pvc"].pop("mount_subpath", None)
            if "storage_request" in kwargs["pvc"]:
                self.create_pvc(pvc_name, **kwargs["pvc"])
            vol_name = "vol-" + uuid.uuid4().hex[:10]
            volume = {
                "name": vol_name,
                "persistentVolumeClaim": {"claimName": pvc_name},
            }
            volume_mount = {
                "name": vol_name,
                "mountPath": pvc_mount_path,
            }
            if pvc_sub_path:
                volume_mount["subPath"] = pvc_sub_path
            if not deployment["spec"]["template"]["spec"].get("volumes"):
                deployment["spec"]["template"]["spec"]["volumes"] = []
            deployment["spec"]["template"]["spec"]["volumes"].append(volume)
            if not deployment["spec"]["template"]["spec"]["containers"][0].get("volumeMounts"):
                deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = []
            deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append(volume_mount)

        if "configmap" in kwargs:
            cm_name = kwargs["configmap"].pop("name")
            cm_mount_path = kwargs["configmap"].pop("mount_path")
            cm_sub_path = kwargs["configmap"].pop("mount_subpath", None)
            if "literals" in kwargs["configmap"] or "files" in kwargs["configmap"]:
                self.create_configmap(cm_name, **kwargs["configmap"])
            vol_name = "vol-" + uuid.uuid4().hex[:10]
            volume = {
                "name": vol_name,
                "configMap": {"name": cm_name},
            }
            volume_mount = {
                "name": vol_name,
                "mountPath": cm_mount_path,
            }
            if cm_sub_path:
                volume_mount["subPath"] = cm_sub_path
            if not deployment["spec"]["template"]["spec"].get("volumes"):
                deployment["spec"]["template"]["spec"]["volumes"] = []
            deployment["spec"]["template"]["spec"]["volumes"].append(volume)
            if not deployment["spec"]["template"]["spec"]["containers"][0].get("volumeMounts"):
                deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = []
            deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append(volume_mount)

        if "init_command" in kwargs:
            if not deployment["spec"]["template"]["spec"].get("initContainers"):
                deployment["spec"]["template"]["spec"]["initContainers"] = []
            deployment["spec"]["template"]["spec"]["initContainers"].append(
                {
                    "name": "run-init-command",
                    "image": "busybox:1.37",
                    "imagePullPolicy": "Always",
                    "command": ["sh", "-c"],
                    "args": [kwargs["init_command"]],
                    "volumeMounts": deployment["spec"]["template"]["spec"]["containers"][0].get("volumeMounts", []),
                }
            )

        if "manifest" in kwargs and isinstance(kwargs["manifest"], dict):
            deployment = recursive_merge(deployment, kwargs["manifest"])

        # inject an additional sidecar container to manage uploads, vxlan/l2tp
        # tunnels and other stuff
        for container in deployment["spec"]["template"]["spec"]["containers"]:
            if not container.get("volumeMounts"):
                container["volumeMounts"] = []
            container["volumeMounts"].append(
                {"name": "shared-data", "mountPath": "/uploads"}
            )
        deployment["spec"]["template"]["spec"]["containers"].append(
            {
                "name": "upload-mgmt-sidecar",
                "image": "hackinsdn/alpine:3.23",
                "imagePullPolicy": "Always",
                "command": ["sleep"],
                "args": ["infinity"],
                "volumeMounts": [
                    {"name": "shared-data", "mountPath": "/uploads"},
                ],
            }
        )
        if not deployment["spec"]["template"]["spec"].get("volumes"):
            deployment["spec"]["template"]["spec"]["volumes"] = []
        deployment["spec"]["template"]["spec"]["volumes"].append(
            {"name": "shared-data", "emptyDir": {}}
        )

        k8s_result = self.k8s.create_from_dict(deployment)

        resource = self._add_resource(
            deployment["apiVersion"], deployment["kind"], name, k8s_result
        )

        # Create Service for publish
        services = {}
        for port in kwargs.get("publish", []):
            if isinstance(port, int):
                port = {"port": port}
            container_port = port.get("port")
            if not isinstance(container_port, int):
                self.log.error(f"Invalid port {port} for publish. Skipping")
                continue
            srv_type = port.get("type", "NodePort")
            if srv_type not in services:
                services[srv_type] = []
            services[srv_type].append(port)
        for srv_type, srv_ports in services.items():
            self.create_service(f"srv-{name}-{srv_type.lower()}", srv_type=srv_type, ports=srv_ports, selector={"app": name}, labels={"app": name})

        # Create Service and Ingress for publish_http
        for attrs in kwargs.get("publish_http", []):
            if not isinstance(attrs, dict):
                self.log.error("Invalid parameter for publish_http - must be a dict. Skipping")
                continue
            if not attrs.get("host"):
                self.log.error("Invalid parameter for publish_http - missing 'host' attribute. Skipping")
                continue
            if not (service_port := attrs.get("service_port")):
                self.log.error("Invalid parameter for publish_http - missing 'service_port' attribute. Skipping")
                continue
            if not attrs.get("name"):
                attrs["name"] = f"{name}-{service_port}"
            attrs["create_service"] = True
            attrs["service_selector"] = {"app": name}
            try:
                res = self.create_ingress(**attrs)
                assert res
            except Exception as exc:
                self.log.error(f"Failed to create ingress: {exc}. Skipping")

        return resource

    def create_pod(self, name, **kwargs):
        """
        Create a k8s Pod.

        All attributes supported are documented in docs/API.md.
        """
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "spec": {
                "containers": [
                    {
                        "name": name,
                        "image": kwargs.get("image", self.default_image),
                        "ports": [],
                    },
                ],
            },
        }

        if "command" in kwargs:
            pod["spec"]["containers"][0]["command"] = kwargs["command"]

        if "args" in kwargs:
            pod["spec"]["containers"][0]["args"] = kwargs["args"]

        if "node_affinity" in kwargs:
            pod["spec"]["affinity"] = {
                "nodeAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": {
                        "nodeSelectorTerms": [{
                            "matchExpressions": [{
                                "key": "kubernetes.io/hostname",
                                "operator": "In",
                                "values": kwargs["node_affinity"].split(","),
                            }],
                        }],
                    },
                },
            }

        if "pvc" in kwargs:
            pvc_name = kwargs["pvc"].pop("name")
            pvc_mount_path = kwargs["pvc"].pop("mount_path")
            pvc_sub_path = kwargs["pvc"].pop("mount_subpath", None)
            if "storage_request" in kwargs["pvc"]:
                self.create_pvc(pvc_name, **kwargs["pvc"])
            vol_name = "vol-" + uuid.uuid4().hex[:10]
            volume = {
                "name": vol_name,
                "persistentVolumeClaim": {"claimName": pvc_name},
            }
            volume_mount = {
                "name": vol_name,
                "mountPath": mount_path,
            }
            if pvc_sub_path:
                volume_mount["subPath"] = pvc_sub_path
            pod["spec"]["volumes"].append(volume)
            pod["spec"]["containers"][0]["volumeMounts"].append(volume_mount)

        if "configmap" in kwargs:
            cm_name = kwargs["configmap"].pop("name")
            cm_mount_path = kwargs["configmap"].pop("mount_path")
            cm_sub_path = kwargs["configmap"].pop("mount_subpath", None)
            if "literals" in kwargs["configmap"] or "files" in kwargs["configmap"]:
                self.create_configmap(cm_name, **kwargs["configmap"])
            vol_name = "vol-" + uuid.uuid4().hex[:10]
            volume = {
                "name": vol_name,
                "configMap": {"name": cm_name},
            }
            volume_mount = {
                "name": vol_name,
                "mountPath": cm_mount_path,
            }
            if cm_sub_path:
                volume_mount["subPath"] = cm_sub_path
            pod["spec"]["volumes"].append(volume)
            pod["spec"]["containers"][0]["volumeMounts"].append(volume_mount)

        if "init_command" in kwargs:
            if not pod["spec"].get("initContainers"):
                pod["spec"]["initContainers"] = []
            pod["spec"]["initContainers"].append(
                {
                    "name": "run-init-command",
                    "image": "busybox:1.37",
                    "imagePullPolicy": "Always",
                    "command": ["sh", "-c"],
                    "args": [kwargs["init_command"]],
                    "volumeMounts": pod["spec"]["containers"][0].get("volumeMounts", []),
                }
            )

        if "manifest" in kwargs and isinstance(kwargs["manifest"], dict):
            pod = recursive_merge(pod, kwargs["manifest"])

        # inject an additional sidecar container to manage uploads, vxlan/l2tp
        # tunnels and other stuff
        for container in pod["spec"]["containers"]:
            if not container.get("volumeMounts"):
                container["volumeMounts"] = []
            container["volumeMounts"].append(
                {"name": "shared-data", "mountPath": "/uploads"}
            )
        pod["spec"]["containers"].append(
            {
                "name": "upload-mgmt-sidecar",
                "image": "hackinsdn/alpine:3.23",
                "imagePullPolicy": "Always",
                "command": ["sleep"],
                "args": ["infinity"],
                "volumeMounts": [
                    {"name": "shared-data", "mountPath": "/uploads"},
                ],
            }
        )
        if not pod["spec"].get("volumes"):
            pod["spec"]["volumes"] = []
        pod["spec"]["volumes"].append(
            {"name": "shared-data", "emptyDir": {}}
        )

        k8s_result = self.k8s.create_from_dict(pod)

        return self._add_resource(
            pod["apiVersion"], pod["kind"], name, k8s_result
        )

    def create_service(self, name, **kwargs):
        """
        Create a k8s service.

        All attributes supported are documented in docs/API.md.
        """
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "spec": {
                "type": kwargs.get("srv_type", "NodePort"),
                "ports": [],
                "selector": {
                    "app": name,
                }
            }
        }
        if kwargs.get("selector"):
            service["spec"]["selector"] = kwargs["selector"]
        if kwargs.get("labels"):
            service["metadata"]["labels"].update(kwargs["labels"])
        for port in kwargs.get("ports", []):
            if isinstance(port, int):
                port = {"port": port}
            container_port = port.get("port")
            if not isinstance(container_port, int):
                self.log.error(f"Invalid port {port}")
                continue
            protocol = port.get("protocol", "TCP")
            service["spec"]["ports"].append({
                "port": container_port,
                "targetPort": container_port,
                "protocol": protocol,
                "name": port.get("name", f"{container_port}-{protocol.lower()}"),
            })

        if "manifest" in kwargs and isinstance(kwargs["manifest"], dict):
            service = recursive_merge(service, kwargs["manifest"])

        k8s_result = self.k8s.create_from_dict(service)

        return self._add_resource(
            service["apiVersion"], service["kind"], name, k8s_result
        )

    def create_pvc(self, name, storage_request, **kwargs):
        """Creates a PersistentVolumeClaim."""
        pvc = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "spec": {
                "accessModes": [kwargs.get("accessModes", "ReadWriteOnce")],
                "resources": {
                    "requests": {
                        "storage": storage_request,
                    },
                },
            },
        }

        if kwargs.get("storageClassName"):
            pvc["spec"]["storageClassName"] = kwargs["storageClassName"]
        if kwargs.get("selector"):
            pvc["spec"]["selector"].update(kwargs["selector"])
        if kwargs.get("labels"):
            pvc["metadata"]["labels"].update(kwargs["labels"])
        if "manifest" in kwargs and isinstance(kwargs["manifest"], dict):
            pvc = recursive_merge(pvc, kwargs["manifest"])

        k8s_result = self.k8s.create_from_dict(pvc)

        return self._add_resource(
            pvc["apiVersion"], pvc["kind"], name, k8s_result
        )

    def create_configmap(self, name, literals={}, files={}):
        """
        Creates a ConfigMap in a Kubernetes from literal values and/or files.
    
        :param name: Name of the ConfigMap to create.
        :param literals: A dictionary of key-value pairs (str: str) for the 'data' field.
        :param files: A dictionary of key-file_path pairs (str: str) for the 'data' field.
                      The file content will be read and used as the value.
        """
        config_map_data = {}

        config_map_data.update(literals)
    
        for key, file_path in files.items():
            if not os.path.exists(file_path):
                print(f"Warning: File not found at {file_path}, skipping.")
                continue
            with open(file_path, 'r') as f:
                config_map_data[key] = f.read()

        configmap = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "data": config_map_data,
        }

        k8s_result = self.k8s.create_from_dict(configmap)

        return self._add_resource(
            configmap["apiVersion"], configmap["kind"], name, k8s_result
        )

    def create_secret_generic(self, name, literals={}, files={}):
        """
        Creates a generic Kubernetes Secret from literal data.
    
        :param name: Name of the secret
        :param literals: Dictionary of key-value pairs (unencoded strings).
        :param files: A dictionary of key-file_path pairs (str: str) for the secret.
                      The file content will be read and used as the value.
        """
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "type": "Opaque",
        }

        if literals:
            secret["string_data"] = literals

        secret_data = {}
        for key, file_path in files.items():
            if not os.path.exists(file_path):
                print(f"Warning: File not found at {file_path}, skipping.")
                continue
            with open(file_path, 'rb') as f:
                secret_data[key] = base64.b64encode(f.read()).decode('utf-8')

        if secret_data:
            secret["data"] = secret_data

        k8s_result = self.k8s.create_from_dict(secret)

        return self._add_resource(
            secret["apiVersion"], secret["kind"], name, k8s_result
        )

    def create_secret_tls(self, name, cert, key, ca=None, hostname=None, ip_addresses=[]):
        """
        Creates a Kubernetes TLS Secret from certificate and key files or auto
        generate a self-signed certificate and key.
    
        :param name: Name of the secret
        :param cert: Either a Path to the TLS certificate file (PEM) or the word
            "auto" to auto generate a self-signed certificate (implies key=auto).
        :param key: Either a Path to the TLS private key file (PEM) or the word
            "auto" to auto generate a self-signed key (implies cert=auto).
        :param ca: Optional. Path to the TLS Certificate Authority / CA file (PEM).
        :param hostname: Optional. String representing the FQDN used when cert=auto
            to define the CN and SAN to be used on the self-signed certificate.
        :param ip_addresses: Optional. List of strings representing the IP addresses
            to be inclused as SAN (Subject Alternative Names). 
        """
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "type": "kubernetes.io/tls",
        }

        if cert == "auto" or key == "auto":
            if not hostname:
                self.log.error(
                    "Failed to create TLS Secret with auto generated cert:"
                    " must provide the hostname!"
                )
                return
            cert_content, key_content = generate_selfsigned_cert(hostname, ip_addresses=ip_addresses)
        elif os.path.exists(cert) and os.path.exists(key):
            with open(cert, 'rb') as f:
                cert_content = f.read()
            with open(key, 'rb') as f:
                key_content = f.read()
        else:
            self.log.error("Failed to create Secret: must provide the cert and key!")
            return

        secret["data"] = {
            "tls.crt": base64.b64encode(cert_content).decode('utf-8'),
            "tls.key": base64.b64encode(key_content).decode('utf-8'),
        }

        if ca:
            if not os.path.exists(ca):
                self.log.error("Failed to create Secret: invalid CA file - file not found!")
                return
            with open(ca, 'rb') as f:
                ca_content = f.read()
            secret["data"]["ca.crt"] = base64.b64encode(ca_content).decode('utf-8')

        k8s_result = self.k8s.create_from_dict(secret)

        return self._add_resource(
            secret["apiVersion"], secret["kind"], name, k8s_result
        )

    def create_secret_docker_registry(self, name, registry_url, username, password, email=None):
        """
        Creates a Kubernetes Docker Registry Secret from credentials.
    
        :param name: Name of the secret
        :param registry_url: URL of the Docker registry
        :param username: Docker username
        :param password: Docker password
        :param email: Optional Docker email

        """
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "type": "kubernetes.io/dockerconfigjson",
        }

        config_data = {
            "auths": {
                registry_url: {
                    "username": username,
                    "password": password,
                    "email": email,
                    "auth": base64.b64encode(f"{username}:{password}".encode('utf-8')).decode('utf-8')
                }
            }
        }
        
        json_config = json.dumps(config_data).encode('utf-8')
        encoded_config = base64.b64encode(json_config).decode('utf-8')

        secret["data"] = {".dockerconfigjson": encoded_config}

        k8s_result = self.k8s.create_from_dict(secret)

        return self._add_resource(
            secret["apiVersion"], secret["kind"], name, k8s_result
        )

    def create_secret(self, name, type, **kwargs):
        """
        Create a Kubernetes Secret with specified type:

        docker_registry: Create a secret for use with a Docker registry.
        generic: Create a secret from a local file, directory, or literal value.
        tls: Create a TLS secret.

        Specific options depends on the type. Check create_secret_generic(),
        create_secret_tls() or create_secret_docker_registry() for more details.
        """
        if type == "generic":
            return self.create_secret_generic(name, **kwargs)
        elif type == "docker_registry":
            return self.create_secret_docker_registry(name, **kwargs)
        elif type == "tls":
            return self.create_secret_tls(name, **kwargs)
        else:
            self.log.error(f"Failed to create Secret: unknown type {type}")

    def create_ingress(self, name, host, ingress_class="nginx", path="/", path_type="Prefix", service_name=None, service_port=None, create_service=False, service_selector=None, enable_tls=False, tls_hosts=None, tls_secret=None, annotations={}):
        """
        Creates a Kubernetes Ingress with specified parameters.
    
        :param name: Name of the Ingress
        :param host: Hostname used for the Ingress
        :param ingress_class: name of the IngressClass cluster controller (ex:
            nginx, haproxy).
        :param path: Path to be matched against the path of an incoming request
        :param path_type: pathType determines the interpretation of the path
            matching. PathType can be one of the following values: Exact -
            Matches the URL path exactly, Prefix - Matches based on a URL path
            prefix split by '/'.
        :param service_name: Name of the Service which provides the backend for
            this ingress. The service must exist in the same namespace.
        :param service_port: Port of the referenced service. When used with
            'create_service=True' it can be a dict with port spec for the
            service to be created.
        :param create_service. Optional. If provided as True, the Service will
            be created as part of the request.
        :param service_selector: Optional. Used with 'create_service=True' to
            define the service selector.
        :param enable_tls: If True, enable the TLS configuration (HTTPS).
        :param tls_hosts: Comma-separated string containing a list of hosts
            included in the TLS cert. Defaults to the Hostname of the Ingress.
        :param tls_secret: name of the secret used to terminate TLS traffic on
            port 443 (HTTPS).

        """
        if not isinstance(service_port, int):
            self.log.error(f"Failed to create Ingress: invalid value for 'service_port' (must be integer)")
            return
        if not service_name:
            service_name = f"srv-{uuid.uuid4().hex[:10]}"

        k8s_req = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": name,
                "labels": {
                    "app": name,
                    "kubernp/Experiment": self.name,
                },
                "ownerReferences": [
                    {
                        "name": self.name,
                        "uid": self.uid,
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                    },
                ],
            },
            "spec": {
                "ingressClassName": ingress_class,
                "rules": [
                    {
                        "host": host,
                        "http": {
                            "paths": [
                                {
                                    "path": path,
                                    "pathType": path_type,
                                    "backend": {
                                        "service": {},
                                    },
                                },
                            ],
                        },
                    }
                ],
            },
        }

        if annotations:
            k8s_req["metadata"]["annotations"] = annotations

        if create_service:
            if not service_selector:
                self.log.error(f"Failed to create service for Ingress: missing required 'service_selector'")
                return
            self.create_service(
                service_name,
                srv_type="ClusterIP",
                ports=[service_port],
                selector=service_selector,
            )

        k8s_req["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"] = {
            "name": service_name,
            "port": {"number": service_port},
        }

        if enable_tls:
            tls = {
                "hosts": (tls_hosts or host).split(","),
            }
            if not k8s_req["spec"].get("tls"):
                k8s_req["spec"]["tls"] = [tls]
            if tls_secret:
                tls["secretName"] = tls_secret
            else:
                # When no TLS Secret was provided, we try an alternate method
                # to fully automated TLS via cert-manager controller and ACME
                # https://cert-manager.io/docs/usage/ingress/#optional-configuration
                sec_name = f"sec-tls-{uuid.uuid4().hex[:10]}"
                tls["secretName"] = sec_name
                if not k8s_req["metadata"].get("annotations"):
                    k8s_req["metadata"]["annotations"] = {}
                k8s_req["metadata"]["annotations"]["kubernetes.io/tls-acme"] = "true"
                self._add_resource("v1", "Secret", sec_name, {})

        k8s_result = self.k8s.create_from_dict(k8s_req)

        return self._add_resource(k8s_req["apiVersion"], k8s_req["kind"], name, k8s_result)

    def _add_resource(self, api_version, kind, name, k8s_result):
        """
        Internal helper function to create a Resource object and update the
        Experiment.
        """
        resource = Resource(
            experiment=self,
            name=name,
            kind=kind,
            api_version=api_version,
            k8s_dict=k8s_result,
        )

        self.resources[(api_version, kind, name)] = {"resource": resource}

        self.resource_names[f"{kind}/{name}"] = (api_version, kind, name)

        self.save(apply=True)

        return resource

    def create_resources(self, resources=[], as_is=False):
        results = []
        for resource in resources:
            if not isinstance(resource, dict):
                self.log.error(f"Invalid resource requested {resource}")
                continue

            if as_is:
                k8s_result = self.k8s.create_from_dict(resource)
                results.append(self._add_resource(
                    resource["apiVersion"],
                    resource["kind"],
                    resource["metadata"]["name"],
                    k8s_result,
                ))
                continue

            kind = resource.pop("kind", None)
            name = resource.pop("name", None)
            if not kind or not name:
                self.log.error(f"Missing required attribute kind/name for {resource=}")
                continue

            func = getattr(self, f"create_{kind.lower()}", None)
            if not callable(func):
                self.log.error(f"Invalid resource requested {resource}")
                continue

            results.append(func(name, **resource))

        return results

    def list_resources(self):
        resource_dict = {"NAME": [], "UID": [], "AGE": [], "STATUS": []}
        for api_ver, kind, name in self.resources:
            try:
                resource = self.k8s.get_resource(api_ver, kind, name)
                self.resources[(api_ver, kind, name)]["resource"].k8s_dict = resource.to_dict()
            except Exception as exc:
                resource = None
            resource_dict["NAME"].append(f"{kind}/{name}")
            if resource:
                resource_dict["AGE"].append(format_duration(resource.metadata.creationTimestamp))
                resource_dict["UID"].append(resource.metadata.uid)
            else:
                resource_dict["AGE"].append("--")
                resource_dict["UID"].append("--")
            resource_dict["STATUS"].append(self.k8s.try_parse_status(resource))

        return show_table(resource_dict, output=self.kubernp.output)

    def list_pod(self, name=None, **kwargs):
        """List Experiment Pods."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_pod(name=name, **kwargs)

    def list_deployment(self, name=None, **kwargs):
        """List Experiment Deployment."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_deployment(name=name, **kwargs)

    def list_service(self, name=None, **kwargs):
        """List Experiment Services."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_service(name=name, **kwargs)

    def list_ingress(self, name=None, **kwargs):
        """List Experiment Ingress."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_ingress(name=name, **kwargs)

    def list_configmap(self, name=None, **kwargs):
        """List Experiment ConfigMap."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_configmap(name=name, **kwargs)

    def list_secret(self, name=None, **kwargs):
        """List Experiment Secret."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_secret(name=name, **kwargs)

    def list_pvc(self, name=None, **kwargs):
        """List Experiment PersistentVolumeClaims."""
        if "label_selector" not in kwargs:
            kwargs["label_selector"] = f"kubernp/Experiment={self.name}"
        return self.k8s.list_pvc(name=name, **kwargs)

    def get_resource(self, name_kind):
        if not (keys := self.resource_names.get(name_kind)):
            self.log.error(f"Resource not found {name_kind}")
            return
        return self.resources[keys]["resource"]

    def delete_resource(self, name_kind, force=False):
        if not (keys := self.resource_names.get(name_kind)):
            self.log.error(f"Resource not found {name_kind}")
            return
        try:
            self.k8s.delete_resource(*keys)
        except Exception as exc:
            self.log.error(f"Failed to delete resource {name_kind}: {exc}")
            if not force:
                return
        self.resource_names.pop(name_kind)
        self.resources.pop(keys)
        self.save(apply=True)

    def delete_resources(self, force=False):
        for name_kind in list(self.resource_names.keys()):
            self.delete_resource(name_kind, force=force)

    def list_events(self, all_resources=False):
        my_resources = set(self.resource_names.keys())
        if all_resources:
            resources = self.k8s.list_all_k8s_resources(label_selector=f"kubernp/Experiment={self.name}", as_dict=True)
            for kind, name in zip(resources["KIND"], resources["RESOURCE NAME"]):
                my_resources.add(f"{kind}/{name}")
        self.k8s.list_events(resources=my_resources)
