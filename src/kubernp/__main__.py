"""KubeRNP main CLI."""
import sys
import tty 
import termios
import select
from threading import Thread
import click
from kubernp import KubeRNP


@click.group()
@click.option("-k", '--kubeconfig', default=None, help='Path to the kubeconfig file to use for Kubernetes requests. Defaults to ~/.kube/config. You can use the KUBECONFIG environment variable to overwrite the default value.')
@click.option("-n", '--namespace', default=None, help='Kubernetes Namespace to be used. If not provided, it will try to be loaded from --kubeconfig. If both fails, an error is raised.')
@click.option("-o", '--output', default=None, help='Format of KubeRNP output; can be either `pandas` or `text`. Defaults to `pandas` in a Jupyter notebook environment; `text` otherwise.')
@click.option('--console-log-level', default="ERROR", help='Log level for console messages. Defaults to `ERROR` (see ``file_log_level`` to other values).')
@click.option('--file-log-level', default="INFO", help='Level of detail in the logs written to file (see `log_file` parameter). Defaults to `INFO`; other possible log levels are `DEBUG`, `WARNING`, `ERROR`, and `CRITICAL`.')
@click.option('--log-file', default=None, help='Path where logs are written; defaults to not save any logs into disk. Example: `/tmp/kubernp.log`.')
@click.pass_context
def cli(ctx, **kwargs):
    """
    KubeRNP is a Python library to facilitate interacting with Kubernetes
    cluster and run experiments.

     Find more information at: https://github.com/hackinsdn/kubernp
    """
    ctx.obj = KubeRNP(**kwargs)

@cli.command()
@click.argument('pod')
@click.option("-c", '--container', default=None, help='Container name. If omitted, the first container in the pod will be chosen.')
@click.option("-s", '--shell', default=None, help='. If omitted, the first container in the pod will be chosen.')
@click.pass_obj
def shell(kubernp, pod, container, shell):
    """Start a shell in a container.."""
    stream = kubernp.k8s.pod_exec(
        pod_name=pod,
        command=["/bin/bash"],
        stderr=True, stdin=True,
        stdout=True, tty=True,
        _preload_content=False,
    )
    is_running = True

    def term_read(timeout=1):
        while is_running and stream.is_open():
            rlist, _, _ = select.select([sys.stdin], [], [], timeout)
            if not rlist:
                continue
            char = sys.stdin.read(1)
            stream.update()
            if stream.is_open():
                stream.write_stdin(char)
    
    t = Thread(target=term_read, args=[])
    
    stdin_fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(stdin_fd)
    try:
        tty.setraw(stdin_fd)
        t.start()
        while stream.is_open():
            data = stream.read_stdout(10)
            if stream.is_open():
                if len(data or "")>0:
                    sys.stdout.write(data)
                    sys.stdout.flush()
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)
        is_running = False

@cli.group()
def list():
    """List Kubernetes resources."""
    pass

@list.command("pod")
@click.argument('name', default=None)
@click.pass_obj
def list_pod(kubernp, name):
    """List Kubernetes Pod"""
    kubernp.k8s.list_pod(name=name)


@list.command("deployment")
@click.argument('name', default=None)
@click.pass_obj
def list_deployment(kubernp, name):
    """List Kubernetes Deployment"""
    kubernp.k8s.list_deployment(name=name)


@list.command("configmap")
@click.argument('name', default=None)
@click.pass_obj
def list_configmap(kubernp, name):
    """List Kubernetes ConfigMap"""
    kubernp.k8s.list_configmap(name=name)


@list.command("secret")
@click.argument('name', default=None)
@click.pass_obj
def list_secret(kubernp, name):
    """List Kubernetes Secret"""
    kubernp.k8s.list_secret(name=name)


@list.command("service")
@click.argument('name', default=None)
@click.pass_obj
def list_service(kubernp, name):
    """List Kubernetes Service"""
    kubernp.k8s.list_service(name=name)


@list.command("ingress")
@click.argument('name', default=None)
@click.pass_obj
def list_ingress(kubernp, name):
    """List Kubernetes Ingress"""
    kubernp.k8s.list_ingress(name=name)


@list.command("pvc")
@click.argument('name', default=None)
@click.pass_obj
def list_pvc(kubernp, name):
    """List Kubernetes PersistentVolumeClaim"""
    kubernp.k8s.list_pvc(name=name)


@list.command("all")
@click.option("-s", '--skip', default="events,events.k8s.io", help='Comma-separated list of kinds to skip from the listing process.')
@click.option("-a", '--show-all', default=False, help='Include resources which API query is returning error (e.g., Forbidden).')
@click.option("-l", '--label-selector', default=None, help='Comma-separated list of labels to filter on, supports `=`, `==`, and `!=` (e.g. -l key1=value1,key2=value2). Matching objects must satisfy all of the specified label constraints.')
@click.pass_obj
def list_all(kubernp, skip, show_all, label_selector):
    """
    Dynamically finds all API resources available and list their instances.
    """
    kubernp.k8s.list_all_k8s_resources(skip=skip.split(","), show_all=show_all, label_selector=label_selector)


@list.command("nodes")
@click.pass_obj
def list_nodes(kubernp):
    """
    Dynamically finds all API resources available and list their instances.
    """
    kubernp.k8s.list_nodes()


if __name__ == "__main__":
    cli()
