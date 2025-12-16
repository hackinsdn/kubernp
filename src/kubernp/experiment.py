"""KubeRNP Experiment"""

import uuid
import re
import logging
import json

from kubernp.utils import recursive_merge, validate_k8s_name
from kubernetes.stream import stream


class Resource:
    """Abstract and encapsulate an Resource for Experiment."""

    def __init__(self, experiment, name, kind, k8s_ref):
        self.experiment = experiment
        self.name = name
        self.kind = kind
        self.k8s_ref = k8s_ref

        self.shell = None
        self.log = self.experiment.log
        self.pod_name = None
        self.container_name = None

    def setup_shell(self):
        # make sure shell is still running
        if self.shell:
            return
        if self.kind not in ["deployment", "pod"]:
            self.log.error(f"Resource {kind}/{name} does not support shell")
            return
        self.pod_name = self.name
        self.container_name = None
        if self.kind == "deployment":
            try:
                pods = self.experiment.k8s.get_resource(
                    "v1", "Pod", None, label_selector="app=testweb"
                ).items
                assert len(pods) == 1
            except:
                self.log.error(f"Failed to obtain container for {kind}/{name}")    
                return
            self.pod_name = pods[0].metadata.name
            self.container_name = pods[0].spec.containers[0].name

        #else:
        #    self.shell = stream(api_instance.connect_get_namespaced_pod_exec
        # TODO: setup shell
        self.shell = True

    def cmd(self, cmd):
        self.setup_shell()
        if not self.shell:
            self.log.error(f"Cannot run cmd into {self.kind}/{self.name}")
            return
        if isinstance(cmd, str):
            cmd = cmd.split()
        if not isinstance(cmd, list):
            self.log.error(f"Invalid command provided, must be string or list")
            return
        print("RUNNING COMMAND ", cmd,  self.pod_name, self.container_name)
        resp = stream(
            self.experiment.k8s.v1_api.connect_get_namespaced_pod_exec,
            name=self.pod_name,
            namespace=self.experiment.k8s.namespace,
            #container=self.container_name,
            command=cmd,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        return resp


class Experiment:
    """Abstract and encapsulate an Experiment with resources."""

    def __init__(self, k8s, name="", description="", resources=[], default_image="alpine:latest", notifications=[], expiration="never"):
        """Create an Experiment."""
        self.k8s = k8s
        self.name = validate_k8s_name(name) if name else f"exp-{uuid.uuid4()}"
        self.description = description
        self.default_image = default_image
        self.notifications = []
        self.expiration = expiration

        self.k8s_ref = None
        self.uuid = None
        self.resources = {}
        self.log = logging.getLogger("kubernp")

        try:
            self.save()
        except Exception as exc:
            self.log.error(f"Failed to create Expirement: {exc}")
            return

        self.create_resources(resources)

    def save(self):
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
            },
        }
        self.k8s_ref = self.k8s.create_from_dict(configmap)

    def load(self):
        try:
            self.k8s_ref = self.k8s.get_resource("v1", "ConfigMap", self.name)
        except Exception as exc:
            self.log.error(f"Failed to load Experiment: {exc}")

    def create_deployment(self, name, **kwargs):
        """
        Create a k8s deployment and optionally publish services.

        All attributes supported are documented in docs/API.md.
        image="", publish=[], publish_http=[], spec={}):
        """
        kind = "deployment"

        deployment = {
          "apiVersion": "apps/v1",
          "kind": "Deployment",
          "metadata": {
            "name": name,
            "labels": {
                "app": name
            },
          },
          "spec": {
            "selector": {
              "matchLabels": {"app": name},
            },
            "template": {
              "metadata": {
                "labels": {"app": name},
              },
              "spec": {
                "containers": [
                  {
                    "name": name,
                    "image": kwargs.get("image", self.default_image),
                    "ports": [],
                  }
                ]
              }
            }
          }
        }

        for port in kwargs.get("publish", []) + kwargs.get("publish_http", []):
            container_port = port
            if isinstance(port, dict):
                container_port = port.get("port")
            if not isinstance(container_port, int):
                self.log.error(f"Invalid port {port}")
                return
            deployment["spec"]["template"]["spec"]["containers"][0]["ports"].append(
                {"containerPort": port}
            )

        if "replicas" in kwargs:
            deployment["spec"]["replicas"] = kwargs["replicas"]

        if "spec" in kwargs and isinstance(kwargs["spec"], dict):
            deployment = recursive_merge(deployment, kwargs["spec"])

        self.log.info(f"Creating Kubernetes deployment: {deployment}")
        k8s_result = self.k8s.create_from_dict(deployment)

        resource = Resource(
            experiment=self,
            name=name,
            kind=kind,
            k8s_ref=k8s_result,
        )

        self.resources[f"{kind}/{name}"] = {
            "request": kwargs|{"name": name, "kind": kind},
            "resource": resource,
        }

        # TODO create services based on publish
        # TODO: for port in publish, create service of the type NodePort
        # TODO: for port in publish_http, create service of the type ClusterIP
        # TODO: for port in publish_http, create ingress
        # TODO: for port in publish_http, if the port has 'hostname' create a DNS entry
        # TODO: for port in publish_http, if the port has 'tls_crt' and tls_key = auto, create a cert and create a secret tls
        for port in kwargs.get("publish", []):
            container_port = port
            if isinstance(port, dict):
                container_port = port.get("port")
            if not isinstance(container_port, int):
                self.log.error(f"Invalid port {port}")
                return

            service = {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": name,
                    "labels": {
                        "app": name,
                    }
                },
                "spec": {
                    "type": "NodePort",
                    "ports": [
                        {
                            "port": container_port,
                            "targetPort": container_port,
                        }
                    ],
                    "selector": {
                        "app": name,
                    }
                }
            }
            self.log.info(f"Creating Kubernetes service: {service}")
            k8s_result = self.k8s.create_from_dict(service)

            resource = Resource(
                experiment=self,
                name=name,
                kind="service",
                k8s_ref=k8s_result,
            )

            self.resources[f"service/{name}"] = {
                "request": {"name": name, "kind": "service", "port": container_port},
                "resource": resource,
            }

        return resource

    def create_resources(self, resources=[]):
        for resource in resources:
            if not isinstance(resource, dict):
                self.log.error(f"Invalid resource requested {resource}")
                continue

            kind = resource.pop("kind", None)
            name = resource.pop("name", None)
            if not kind or not name:
                self.log.error(f"Missing required attribute kind/name for {resource=}")
                continue

            func = getattr(self, f"create_{kind}", None)
            if not callable(func):
                self.log.error(f"Invalid resource requested {resource}")
                continue

            result = func(name, **resource)
