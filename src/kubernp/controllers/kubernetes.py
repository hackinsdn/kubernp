"""KubeRNP Kubernetes controller"""

from kubernetes import config, client
from kubernetes.dynamic.client import DynamicClient


class K8sController():
    def __init__(self, kubeconfig, namespace):
        self.kubeconfig = kubeconfig
        self.namespace = namespace

        self.v1_api = None
        self.apps_v1_api = None
        self.k8s_client = None

        self.load_config()

    def load_config(self):
        config.load_kube_config(config_file=self.kubeconfig)
        if not self.namespace:
            try:
                _, current_context = config.list_kube_config_contexts()
                self.namespace = current_context["context"]["namespace"]
            except:
                self.namespace = None
        if not self.namespace:
            raise ValueError(
                "Could not determine Kubernetes namespace. Please provide the"
                " 'namespace' as paramter or update your kubeconfig"
            )

        self.v1_api = client.CoreV1Api()
        self.apps_v1_api = client.AppsV1Api()
        self.k8s_client = client.ApiClient()

    def create_from_dict(self, resource):
        resource_api = DynamicClient(self.k8s_client).resources.get(
            api_version=resource["apiVersion"], kind=resource["kind"]
        )
        resp = resource_api.server_side_apply(
            body=resource, field_manager="python-client", namespace=self.namespace
        )
        return resp.to_dict()

    def delete_resource(self, api_version, kind, name):
        try:
            resource_api = DynamicClient(self.k8s_client).resources.get(
                api_version=api_version, kind=kind
            )
        except:
            self.log.error(f"Resource API not found for {api_version=} {kind=}")
            return False
        resp = resource_api.delete(name, namespace=self.namespace)
        return resp

    def get_resource(self, api_version, kind, name, **kwargs):
        try:
            resource_api = DynamicClient(self.k8s_client).resources.get(
                api_version=api_version, kind=kind
            )
        except:
            self.log.error(f"Resource API not found for {api_version=} {kind=}")
            return False
        resp = resource_api.get(name, namespace=self.namespace, **kwargs)
        return resp
