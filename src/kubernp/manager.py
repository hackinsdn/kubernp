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
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pandas as pd
from IPython import get_ipython
from IPython.core.display_functions import display
from tabulate import tabulate

from kubernp.controllers.kubernetes import K8sController
from kubernp.experiment import Experiment


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
            ``"${HOME}/.kube/config"``.
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
        self.kubeconfig = str(kubeconfig or Path.home() / ".kube" / "config")
        self.namespace = namespace
        self.output = output
        if not self.output:
            self.output = "pandas" if self.is_jupyter() else "text"
        self.console_log_level = console_log_level
        self.file_log_level = file_log_level
        self.log_file = log_file

        self.k8s = None
        self.log = None

        self.initialize()

    def initialize(self):
        self.setup_logging()
        self.load_k8s()

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

    def load_k8s(self):
        try:
            self.k8s = K8sController(self.kubeconfig, self.namespace)
        except Exception as exc:
            msg = f"Error while loading kubernetes controller: {exc}"
            err = traceback.format_exc().replace("\n", ", ")
            self.log.error(msg + " -- " + err)

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
        return self.show_table(
            self.get_config(),
            output=output,
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

    def create_show_table(self, data, fields=None, pretty_names_dict={}):
        """
        Based on FABRIC fabrictestbed-extensions package.

        Form a table that we can display.
        """
        table = []
        if fields is None:
            for key, value in data.items():
                if key in pretty_names_dict:
                    table.append([pretty_names_dict[key], value])
                else:
                    table.append([key, value])
        else:
            for field in fields:
                value = data[field]
                if field in pretty_names_dict:
                    table.append([pretty_names_dict[field], value])
                else:
                    table.append([field, value])

        return table

    def show_table(
        self,
        data,
        output=None,
        quiet=False,
        fields=None,
        title="",
        pretty_names_dict={},
    ):
        """
        Based on FABRIC fabrictestbed-extensions package.

        Form a table that we can display.
        """
        if output is None:
            output = self.output

        table = self.create_show_table(
            data, fields=fields, pretty_names_dict=pretty_names_dict
        )

        if output == "text" or output == "default":
            return self.show_table_text(table, quiet=quiet)
        elif output == "json":
            return self.show_table_json(data, quiet=quiet)
        elif output == "dict":
            return self.show_table_dict(data, quiet=quiet)
        elif output == "pandas" or output == "jupyter_default":
            return self.show_table_jupyter(
                table,
                headers=fields,
                title=title,
                quiet=quiet,
            )
        else:
            log.error(f"Unknown output type: {output}")

    def show_table_text(self, table, quiet=False):
        """
        Based on FABRIC fabrictestbed-extensions package.

        Make a table in text format.
        """
        printable_table = tabulate(table)
        if not quiet:
            print(f"\n{printable_table}")
            return
        return printable_table

    def show_table_json(self, data, quiet=False):
        """
        Based on FABRIC fabrictestbed-extensions package.

        Make a table in JSON format.
        """
        json_str = json.dumps(data, indent=4)

        if not quiet:
            print(f"{json_str}")
            return

        return json_str

    def show_table_dict(self, data, quiet=False):
        """
        Based on FABRIC fabrictestbed-extensions package.

        Show the table.
        """
        if not quiet:
            print(f"{data}")
            return

        return data

    def show_table_jupyter(
        self, table, headers=None, title="", title_font_size="1.25em", quiet=False
    ):
        """
        Based on FABRIC fabrictestbed-extensions package.

        Make a table in text form suitable for Jupyter notebooks.

        You normally will not use this method directly; you should
        rather use :py:meth:`show_table()`.

        :param table: A list of lists.
        :param title: The table title.
        :param title_font_size: Font size to use for the table title.
        :param quiet: Setting this to `False` causes the table to be
            displayed.

        :return: a Pandas dataframe.
        :rtype: pd.DataFrame
        """
        printable_table = pd.DataFrame(table)

        properties = {
            "text-align": "left",
            "border": f"1px #202020 solid !important",
        }

        printable_table = printable_table.style.set_caption(title)
        printable_table = printable_table.set_properties(**properties, overwrite=False)
        printable_table = printable_table.hide(axis="index")
        printable_table = printable_table.hide(axis="columns")

        printable_table = printable_table.set_table_styles(
            [
                {
                    "selector": "tr:nth-child(even)",
                    "props": [
                        ("background", "#dbf3ff"),
                        ("color", "#202020"),
                    ],
                }
            ],
            overwrite=False,
        )
        printable_table = printable_table.set_table_styles(
            [
                {
                    "selector": "tr:nth-child(odd)",
                    "props": [
                        ("background", "#ffffff"),
                        ("color", "#202020"),
                    ],
                }
            ],
            overwrite=False,
        )

        caption_props = [
            ("text-align", "center"),
            ("font-size", "150%"),
        ]

        printable_table = printable_table.set_table_styles(
            [{"selector": "caption", "props": caption_props}], overwrite=False
        )

        if not quiet:
            display(printable_table)
            return

        return printable_table

    def create_experiment(self, **kwargs):
        return Experiment(self.k8s, **kwargs)
