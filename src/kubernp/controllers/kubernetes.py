"""KubeRNP Kubernetes controller"""

import time
import logging

from kubernetes import config, client, watch
from kubernetes.client.exceptions import ApiException
from kubernetes.dynamic.client import DynamicClient
from kubernetes.stream import stream

from kubernp.utils import format_duration
from kubernp.output import show_table


class K8sController():
    def __init__(self, kubernp, kubeconfig, namespace):
        self.kubernp = kubernp
        self.kubeconfig = str(kubeconfig)
        self.namespace = namespace

        self.v1_api = None
        self.apps_v1_api = None
        self.k8s_client = None
        self.nodes = {}
        self.node_info = {}
        self.nodes_last_updated = 0

        self.log = logging.getLogger("kubernp")

        self.load_config()

    def load_config(self):
        config.load_kube_config(config_file=self.kubeconfig)
        if not self.namespace:
            try:
                _, current_context = config.list_kube_config_contexts(config_file=self.kubeconfig)
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

    def create_from_dict(self, resource, apply=False):
        """
        Create Kubernetes resource from a dict. The resource can be created
        by using the create method (default) or apply.
        """
        self.log.debug(f"Creating Kubernetes resource: {resource=} {apply=}")
        resource_api = DynamicClient(self.k8s_client).resources.get(
            api_version=resource["apiVersion"], kind=resource["kind"]
        )
        try:
            if apply:
                resp = resource_api.server_side_apply(
                    body=resource,
                    namespace=self.namespace,
                    field_manager="python-client",
                    force_conflicts=True,
                )
            else:
                resp = resource_api.create(resource, namespace=self.namespace)
        except ApiException as api_exc:
            self.log.error(f"Failed to create resource reason={api_exc.reason}: {api_exc.body}")
            resp = None
        if not resp:
            raise Exception("Failed to create Kubernetes resource")
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

    def update_resource(self, api_version, kind, name, body):
        try:
            resource_api = DynamicClient(self.k8s_client).resources.get(
                api_version=api_version, kind=kind
            )
        except:
            self.log.error(f"Resource API not found for {api_version=} {kind=}")
            return False
        resp = resource_api.patch(name=name, body=body, namespace=self.namespace)
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

    def update_nodes(self):
        if time.time() - self.nodes_last_updated < 60:
            return
        self.nodes = {}
        self.node_info = {}
        resp = self.v1_api.list_node()
        for node in resp.items:
            self.nodes[node.metadata.name] = node
            # Check for node status
            status = "NotReady"
            for cond in node.status.conditions:
                if cond.type == "Ready" and cond.status == "True":
                    status = "Ready"
                    break
            # Check for node's internal IP addr
            internal_ip = None
            for addr in node.status.addresses:
                if addr.type == "InternalIP":
                    internal_ip = addr.address
                    break
            # Check for node roles based on standard role labels
            roles = set()
            for label_key, label_value in node.metadata.labels.items():
                if label_key.startswith("node-role.kubernetes.io/"):
                    role = label_key.split("/")[-1]
                    roles.add(role)
            for taint in (node.spec.taints or []):
                if taint.key == "node-role.kubernetes.io/control-plane" and taint.effect == "NoSchedule":
                    roles.add("control-plane")
                    break
            else:
                roles.add("worker")

            if not roles:
                roles.add("<none>")

            self.node_info[node.metadata.name] = {
                "status": status,
                "internal_ip": internal_ip,
                "roles": ",".join(roles),
            }
        self.nodes_last_updated = time.time()

    def get_node_ip(self, name):
        self.update_nodes()
        return self.node_info.get(name, {}).get("internal_ip", None)

    def list_nodes(self, as_dict=False):
        """
        List Kubernetes nodes and their basic information
        """
        self.update_nodes()
        node_table = {"NAME": [], "STATUS": [], "ROLES": [], "INTERNAL-IP": []}
        for name, node in self.nodes.items():
            node_table["NAME"].append(name)
            node_table["STATUS"].append(self.node_info[name]["status"])
            node_table["ROLES"].append(self.node_info[name]["roles"])
            node_table["INTERNAL-IP"].append(self.node_info[name]["internal_ip"])

        if as_dict:
            return node_table

        show_table(node_table, output=self.kubernp.output)

    def list_events(self, name=None, kind=None, type=None, resources=[], as_dict=False):
        """
        List the most important information about Kubernetes events. You can
        request events pertaining to a specified resource name, kind, type, or
        filtered by resources of interest (list of kind/name). You can also
        return a dict instead of print the events.
        """
        events = self.v1_api.list_namespaced_event(self.namespace)
        filtered_events = []
        for event in events.items:
            if name is not None and event.involved_object.name != name:
                continue
            if kind is not None and event.involved_object.kind != kind:
                continue
            if type is not None and event.involved_object.type != type:
                continue
            if resources and f"{event.involved_object.kind}/{event.involved_object.name}" not in resources:
                continue
            filtered_events.append(event)

        if not filtered_events:
            if as_dict:
                return {}
            print(f"No events found in '{self.namespace}' namespace.")
            return

        events_dict = []
        events_table = {"LAST SEEN": [], "TYPE": [], "REASON": [], "OBJECT": [], "MESSAGE": []}
        for event in filtered_events:
            if as_dict:
                events_dict.append(event.to_dict())
                continue
            events_table["LAST SEEN"].append(format_duration(event.last_timestamp))
            events_table["TYPE"].append(event.type)
            events_table["REASON"].append(event.reason)
            events_table["OBJECT"].append(f"{event.involved_object.kind}/{event.involved_object.name}")
            events_table["MESSAGE"].append(event.message)

        if as_dict:
            return events_dict

        show_table(events_table, output=self.kubernp.output)

    def _check_ownership_filter(self, item, owners):
        """
        Check ownership: if item has any ownerReference belonging to owners.
        """
        if not owners:
            return True
        for owner_ref in (item.metadata.ownerReferences or []):
            if f"{owner_ref.kind}/{owner_ref.name}" in owners:
                return True
        return False

    def list_resources(self, api_version, kind, name, **kwargs):
        """
        List Kubernetes resources by api_version/kind/name.

        Parameters:

        :param as_dict: Boolean. Return the list of resources instead of printing
        :param label_selector: filter the resources by labels
        :param ownership_selector: filter resources by ownerReferences
        :param extra_columns: extra columns to be added. The format is a dict
            with the keys being the column name and the value being the field
            specification expressed as a JSONPath expression (example 
            '.metadata.name' or 'len(item.status.containerStatuses)')
        """
        resource_table = {"KIND/NAME": [], "STATUS": [], "AGE": []}
        result = []
        if extra_columns := kwargs.pop("extra_columns", {}):
            for col in extra_columns:
                resource_table[col] = []
        owners = set(kwargs.pop("ownership_selector", []))
        resources = self.get_resource(api_version, kind, name, **kwargs)
        for item in resources.items:
            if not self._check_ownership_filter(item, owners):
                continue
            if kwargs.get("as_dict"):
                result.append(item)
                continue
            resource_table["KIND/NAME"].append(f"{item.kind}/{item.metadata.name}")
            resource_table["STATUS"].append(self.try_parse_status(item))
            resource_table["AGE"].append(format_duration(item.metadata.creationTimestamp))
            for col, jsonpath in extra_columns.items():
                if jsonpath.startswith("."):
                    jsonpath = f"item{jsonpath}"
                try:
                    resource_table[col].append(eval(jsonpath))
                except Exception as exc:
                    if kwargs.get("debug"):
                        print(f"Error processing jsonpath={jsonpath}: {exc}")
                    resource_table[col].append("(error)")

        if kwargs.get("as_dict"):
            return result

        if resource_table["KIND/NAME"]:
            show_table(resource_table, output=self.kubernp.output)
        else:
            print(f"No {kind} found in {self.namespace} namespace.")

    def list_pod(self, name=None, **kwargs):
        """
        List Kubernetes pods. You can filter the list using a label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        if "extra_columns" not in kwargs:
            kwargs["extra_columns"] = {
                "NODE": ".spec.nodeName",
                "IP": ".status.podIP",
            }
        return self.list_resources("v1", "Pod", name, **kwargs)

    def list_deployment(self, name=None, **kwargs):
        """
        List Kubernetes Deployment. You can filter by label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        return self.list_resources("apps/v1", "Deployment", name, **kwargs)

    def list_configmap(self, name=None, **kwargs):
        """
        List Kubernetes ConfigMap. You can filter by label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        if "extra_columns" not in kwargs:
            kwargs["extra_columns"] = {
                "DATA": "len(item.data.to_dict())",
            }
        return self.list_resources("v1", "ConfigMap", name, **kwargs)

    def list_secret(self, name=None, **kwargs):
        """
        List Kubernetes Secret. You can filter by label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        return self.list_resources("v1", "Secret", name, **kwargs)

    def list_service(self, name=None, **kwargs):
        """
        List Kubernetes Service. You can filter by label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        return self.list_resources("v1", "Service", name, **kwargs)

    def list_ingress(self, name=None, **kwargs):
        """
        List Kubernetes Ingress. You can filter by label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        return self.list_resources("networking.k8s.io/v1", "Ingress", name, **kwargs)

    def list_pvc(self, name=None, **kwargs):
        """
        List Kubernetes Ingress. You can filter by label selector
        (example label_selector="app=xpto-foobar,mylabel.k8s.io/test=123")
        """
        return self.list_resources("v1", "PersistentVolumeClaim", name, **kwargs)

    def list_all_k8s_resources(self, skip=['events', 'events.k8s.io'], show_all=False, as_dict=False, label_selector=None):
        """
        Dynamically finds all API resources available in your cluster and lists
        instances of each type, similar to:
            kubectl api-resources | xargs kubectl get

        :param skip: allow skipping some problematic or unhelpful resources
        """
        resource_table = {"KIND": [], "APIVERSION": [], "RESOURCE NAME": [], "STATUS": []}
        for resource in DynamicClient(self.k8s_client).resources.search():
            if resource.name in skip or not resource.namespaced:
                continue
            if "list" not in resource.verbs or resource.kind.endswith("List"):
                continue
            try:
                resource_list = resource.get(namespace=self.namespace, label_selector=label_selector)
            except ApiException as api_exc:
                if show_all:
                    resource_table["KIND"].append(resource.kind)
                    resource_table["APIVERSION"].append(resource.group_version)
                    resource_table["RESOURCE NAME"].append("--")
                    resource_table["STATUS"].append(f"error: {api_exc.reason}")
                continue
            for item in resource_list.items:
                resource_table["KIND"].append(resource.kind)
                resource_table["APIVERSION"].append(resource.group_version)
                resource_table["RESOURCE NAME"].append(item.metadata.name)
                resource_table["STATUS"].append(self.try_parse_status(item))
            if not resource_list.items and show_all:
                resource_table["KIND"].append(resource.kind)
                resource_table["APIVERSION"].append(resource.group_version)
                resource_table["RESOURCE NAME"].append("--")
                resource_table["STATUS"].append("--")

        if as_dict:
            return resource_table

        show_table(resource_table, output=self.kubernp.output)

    def try_parse_status(self, resource):
        """
        Try to parse and return the status of a resource. In Kubernetes, status
        values describe the current state of a resource. Common status values
        vary by the specific object type (e.g., Pod, Node), but generally fall
        into categories like phases and conditions.
        """
        if not resource or resource.kind in ["Ingress", "ConfigMap", "Service"]:
            return "--"
        if resource.kind in ["Deployment", "ReplicaSet"]:
            return f"{resource.status.readyReplicas or 0}/{resource.status.replicas}"
        if resource.kind in ["PersistentVolumeClaim"]:
            return resource.status.phase
        if resource.kind == "Pod":
            if resource.metadata.deletionTimestamp:
                return "Terminating"
            for status in (resource.status.containerStatuses or []):
                if not status.ready:
                    try:
                        return status.state.waiting.reason
                    except:
                        return "NotReady"
            return resource.status.phase
        if resource.kind == "Topology":
            total = ready = 0
            for node, status in resource.status.nodeReadiness.items():
                total += 1
                ready += status == "ready"
            return f"{ready}/{total}"
        return resource.status or "--"

    def wait_deployment_running(self, name, timeout=60, step=2, verbose=False):
        """
        Waits for a Kubernetes deployment to be in the 'running' state (available).
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                deployment_status = self.apps_v1_api.read_namespaced_deployment_status(
                    name=name,
                    namespace=self.namespace
                )

                spec_replicas = deployment_status.spec.replicas
                status_available_replicas = deployment_status.status.available_replicas

                if spec_replicas is not None and status_available_replicas is not None:
                    if status_available_replicas == spec_replicas:
                        if verbose:
                            print(f"Deployment '{name}' is running and ready.")
                        return True, "ok"

                if verbose:
                    print(
                        f"Waiting for deployment '{name}'... "
                        f"Available replicas: {status_available_replicas or 0}/{spec_replicas or 0}"
                    )

            except ApiException as api_exc:
                return False, f"Error accessing Deployment status: {api_exc.reason}"

            time.sleep(step)

        return False, f"Timeout waiting for '{name}' to become ready."

    def wait_pod_running(self, name, timeout=60, step=2, verbose=False):
        """
        Waits for a specific pod to reach the 'Running' phase.
        """
        w = watch.Watch()
        start_time = time.time()

        try:
            for event in w.stream(func=self.v1_api.list_namespaced_pod,
                                  namespace=self.namespace,
                                  timeout_seconds=timeout):

                obj = event['object']
                if obj.metadata.name == name:
                    pod_phase = obj.status.phase

                    if pod_phase == "Running":
                        # Check if all containers are also ready
                        all_ready = True
                        for container_status in obj.status.container_statuses:
                            if not container_status.ready:
                                all_ready = False
                                break

                        if all_ready:
                            end_time = time.time()
                            if verbose:
                                print(f"Pod '{name}' is Running and Ready in {end_time - start_time:.2f} seconds.")
                            w.stop()
                            return True, "ok"

                    elif pod_phase == "Failed" or pod_phase == "Succeeded":
                        w.stop()
                        return False, f"Pod '{name}' reached terminal phase: {pod_phase}. Stopping wait."

        except watch.WatchTermination:
            return False, f"Watch stream terminated or timed out after {timeout} seconds."
        except ApiException as api_exc:
            return False, f"Error accessing Pod status: {api_exc.reason}"

        return False, "Timeout waiting for Pod to be running"

    def pod_exec(self, pod_name, command, container=None, stderr=True, stdin=True, stdout=True, tty=True, _preload_content=True):
        """
        Establish a websocket with Pod to execute command and return a stream.
        """
        return stream(
            self.v1_api.connect_get_namespaced_pod_exec,
            pod_name,
            self.namespace,
            container=container,
            command=command,
            stderr=stderr, stdin=stdin,
            stdout=stdout, tty=tty,
            _preload_content=_preload_content
        )
