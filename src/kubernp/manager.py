"""
KubeRNPManager allows you to orchestrate a Kubernetes cluster to create and run
experiments via operations such as:

- Query cluster resources
- Create, modify, and delete experiments
- etc.
"""

import json
import logging
import os
import traceback
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path

from IPython import get_ipython

from kubernp.controllers.kubernetes import K8sController
from kubernp.controllers.mininetsec import MininetSecController
from kubernp.controllers.containerlab import ContainerlabController
from kubernp.experiment import Experiment
from kubernp.output import show_table


class KubeRNPManager:
    """Main class to interact with the Kubernetes cluster."""

    def __init__(
        self,
        kubeconfig=None,
        namespace=None,
        output=None,
        console_log_level="ERROR",
        file_log_level="INFO",
        log_file=None,
    ):
        """
        :param kubeconfig: Path to kubernetes configuration file. Defaults to
            ``"${HOME}/.kube/config"``. You can use the KUBECONFIG environment
            variable to overwrite the default value.
        :param namespace: Kubernetes Namespace to be used. If not provided, it
            will try to be loaded from ``kubeconfig``. If both fails, an error
            is raised.
        :param output: Format of KubeRNP output; can be either ``"pandas"`` or
            ``"text"``. Defaults to ``"pandas"`` in a Jupyter notebook
            environment; ``"text"`` otherwise.
        :param log_file: Path where logs are written; defaults to not save any
            logs into disk. Example: ``"/tmp/kubernp.log"``.
        :param file_log_level: Level of detail in the logs written to file (see
            ``log_file`` parameter). Defaults to ``"INFO"``; other possible log
            levels are ``"DEBUG"``, ``"WARNING"``, ``"ERROR"``, and ``"CRITICAL"``.
        :param console_log_level: Log level for console messages. Defaults to
            ``"ERROR"`` (see ``file_log_level`` to other values).
        """
        self.kubeconfig = Path(kubeconfig or os.environ.get("KUBECONFIG", "~/.kube/config"))
        self.namespace = namespace
        self.output = output
        if not self.output:
            self.output = "pandas" if self.is_jupyter() else "text"
        self.console_log_level = console_log_level
        self.file_log_level = file_log_level
        self.log_file = log_file

        self.k8s = None
        self.log = None
        self.mnsec = None
        self.clab = None

        self.initialize()

    def initialize(self):
        self.setup_logging()
        self.setup_k8s()

    def setup_logging(self):
        self.log = logging.getLogger("kubernp")
        default_log_format = (
            "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
        )
        self.log.setLevel(logging.INFO)
        if self.log_file:
            file_handler = RotatingFileHandler(
                self.log_file, backupCount=int(5), maxBytes=int(1024 * 1024 * 5)
            )
            file_handler.setFormatter(logging.Formatter(default_log_format))
            file_handler.setLevel(logging.getLevelName(self.file_log_level))
            self.log.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.getLevelName(self.console_log_level))
        self.log.addHandler(console_handler)

    def setup_k8s(self):
        try:
            self.k8s = K8sController(self, self.kubeconfig, self.namespace)
        except Exception as exc:
            msg = f"Error while loading kubernetes controller: {exc}"
            err = traceback.format_exc().replace("\n", ", ")
            self.log.error(msg + " -- " + err)
            return
        self.mnsec = MininetSecController(self)
        self.c9s = ContainerlabController(self)

    def is_jupyter(self):
        """Helper function to determine if Python code is currently executing
        within a Jupyter Notebook environment"""
        if "JPY_PARENT_PID" in os.environ:
            return True
        try:
            shell = get_ipython().__class__.__name__
            if shell == "ZMQInteractiveShell":
                return True  # Running in Jupyter Notebook/Lab
            elif shell == "TerminalInteractiveShell":
                return False  # Running in IPython terminal
            else:
                return False  # Other environments
        except NameError:
            return False

    def show_config(self, output=None, quiet=False):
        return show_table(
            self.get_config(),
            output=output or self.output,
            quiet=quiet,
        )

    def get_config(self):
        return {
            "kubeconfig": self.kubeconfig,
            "namespace": self.k8s.namespace,
            "output": self.output,
            "console_log_level": self.console_log_level,
            "file_log_level": self.file_log_level,
            "log_file": self.log_file,
        }

    def create_experiment(self, name=None, **kwargs):
        return Experiment(self, name=name, **kwargs)

    def list_experiments(self):
        try:
            results = self.k8s.get_resource("v1", "ConfigMap", None, label_selector="kubernp/kind=Experiment").items
        except Exception as exc:
            self.log.error(f"Failed to list experiments: {exc}")
            return
        experiments = {"NAME": [], "DESCRIPTION": [], "CREATED_AT": [], "#RESOURCES": []}
        for exp in results:
            experiments["NAME"].append(exp.metadata.name)
            experiments["DESCRIPTION"].append(exp.data.get("description") or "--")
            experiments["CREATED_AT"].append(exp.metadata.creationTimestamp)
            experiments["#RESOURCES"].append(len(json.loads(exp.data.get("resources", '[]'))))

        return show_table(experiments, output=self.output, empty_msg=f"No experiments found in namespace {self.k8s.namespace}.")

    def load_experiment(self, name, skip_errors=False):
        return Experiment(self, name=name, load=True, skip_errors=skip_errors)

    def delete_experiment(self, exp):
        if isinstance(exp, str):
            try:
                exp = Experiment(self, name=exp, load=True)
            except Exception as exc:
                self.log.error(f"Failed to load Experiment for removal: {exc}")
                return
        if not isinstance(exp, Experiment):
            raise ValueError("Argument must be a string (experiment name) or Experiment instance")
        exp.delete_resources(force=True)
        try:
            self.k8s.delete_resource("v1", "ConfigMap", exp.name)
        except:
            pass

    def healthcheck_nodes(self, image="busybox:1.37", command=["sleep", "infinity"], test_cmd="wget http://ifconfig.io/ip -O -", expect_func=None, timeout=30, nodes=None, quiet=False):
        """
        Run a health check into Kubernetes nodes and return their status.

        Arguments:
        :param image: docker image to be used in the healthcheck pod
        :param command: command to be used in the healthcheck container
        :param test_cmd: test command to be executed on the created pod
        :param expect_func: expect function to be used to verify if test_cmd was
            success or not, the function should return the expected value
            returned by test_cmd. The function receives one argument:  the node
            name where test_cmd was executed. The value from expect_func is
            compared with result from test_cmd to determine node is healthy.
        :timeout: timeout to wait for the Pod to be running and for test_cmd to
            execute.
        :nodes: list of node names to check. If not provided, defaults to worker
            nodes from the current cluster.
        :quiet: dont print messages about what steps are being executed.
        """

        def print_cond(msg):
            if not quiet:
                print(msg)

        health_nodes = []
        reason = {}
        self.k8s.update_nodes()
        if nodes is None:
            nodes = [
                node for node, info in self.k8s.node_info.items()
                if info["status"] == "Ready" and "worker" in info["roles"]
            ]
        if not nodes:
            return health_nodes, reason

        exp = self.create_experiment()
        pods = {}
        for node in nodes:
            print_cond(f"Healthcheck #1: creating pod on node {node}")
            try:
                pods[node] = exp.create_pod(
                    name=f"pod-test-{node}-{exp.uid[:8]}",
                    image=image,
                    command=command,
                    node_affinity=node
                )
            except Exception as exc:
                print_cond(f"-> Failed to create pod on node {node}")
                reason[node] = f"Failed to create test pod: {exc}"

        running_pods = []
        for node in pods:
            print_cond(f"Healthcheck #2: wait pod running {node=} {timeout=}")
            is_running, msg = pods[node].wait_running(timeout=timeout)
            if is_running:
                running_pods.append(node)
            else:
                print_cond(f"-> pod not running {node=} {msg=}")
                reason[node] = msg

        results = {}
        extra_info = {}
        for n in running_pods:
            extra_info[n] = pods[n].get_k8s()
            print_cond(f"Healthcheck #3: exec test command node={n}")
            try:
                results[n] = pods[n].exec(f"timeout {timeout} {test_cmd}").strip()
            except Exception as exc:
                print_cond(f"-> failed to run test command node={n} {exc=}")
                reason[n] = f"Failed to exec test pod commands on node={n}: {exc}"

        if expect_func is None:
            expect_func = lambda n: self.k8s.node_info[n]["internal_ip"]
        for node, result in results.items():
            print_cond(f"Healthcheck #4: check result from test cmd {node=}")
            expected = expect_func(node)
            if result == expected:
                health_nodes.append(node)
            else:
                print_cond(f"-> mismatch result from {node=}")
                reason[node] = f"Mismatch on test output: {expected=} {result=}. Extra info: {extra_info[node]}"

        self.delete_experiment(exp)

        return health_nodes, reason
