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

import yaml
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

    def create_experiment(self, **kwargs):
        return Experiment(self, **kwargs)

    def create_experiment_from_file(self, filename, name=None, **kwargs):
        """
        Create a Kubernetes experiment/resources based on a file. JSON and YAML
        formats are accepted. We apply some heuristics to try to identify if
        experiment being created is based on HackInSDN/Mininet-Sec scenario or
        ContainerLab scenario.

        Parameters:
        :param filename: path to the file that describes the experiment to be
            created (manifest file), YAML or JSON. It can be a standard
            Kubernetes manifest with multiple resources, a Mininet-Sec/HackInSDN
            manifest, a ContainerLab topology.
        :param name: Optional. String with the experiment name

        Additional Parameters:
        :param mnsec_image: name of the mininet-sec image (defaults to
            hackinsdn/mininet-sec)
        :param quiet: Boolean. When true do not print information on each step
        """
        if not kwargs.get("quiet", False):
            print(f"Loading content from file {filename}")
        try:
            content = Path(filename).expanduser().read_text()
        except Exception as exc:
            print(exc)
            return None
        if self.mnsec.is_mininetsec(content):
            if not kwargs.get("quiet", False):
                print(f"Detected a Mininet-Sec manifest. Preparing the lab...")
            objs = self.mnsec.prepare_lab(content, **kwargs)
            if not objs:
                print(f"Failed to convert Mininet-sec Lab")
                return
        elif self.c9s.is_containerlab(filename):
            if not kwargs.get("quiet", False):
                print(f"Detected a Containerlab topology. Converting to clab...")
            objs = self.c9s.prepare_lab(filename, **kwargs)
            if not objs:
                print(f"Failed to convert Containerlab Lab")
                return
        else:
            if not kwargs.get("quiet", False):
                print(f"Generic Kubernetes manifest. Loading resources...")
            try:
                objs = json.loads(content)
                objs = [objs] if isinstance(objs, dict) else objs
            except:
                try:
                    objs = list(yaml.safe_load_all(content))
                except:
                    print("Failed to load content from file: must be YAML or JSON")
                    return None

        if not kwargs.get("quiet", False):
            print(f"Creating experiment...")
        exp = self.create_experiment(name=name)

        if not kwargs.get("quiet", False):
            print(f"Creating resources...")
        exp.create_resources(objs, as_is=True)

        if not kwargs.get("quiet", False):
            print(f"All done!")
        return exp

    def list_experiments(self):
        try:
            results = self.k8s.get_resource("v1", "ConfigMap", None, label_selector="kubernp/kind=Experiment").items
        except:
            results = []
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
