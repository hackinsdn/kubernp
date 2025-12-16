# KubeRNP Python Client Library

## Overview

This is the implementation of a Python library, otherwise known as
"KubeRNP", for interacting with RNP Kubernetes cluster.

You can use this lib with a JupyterHub instance or directly our your
Python SDE. Docs can be found here (TBD).

## Installing KubeRNP

You can install released versions of KubeRNP from PyPI

```
pip install kubernp
```

If you need the current development version of KubeRNP, install it from
the git repository:

```
pip install git+https://github.com/hackinsdn/kubernp@main
```

Due to the number of dependencies, we recommend install KubeRNP in a
virtual environment.

**NOTE**: This package has been tested and verified to work with Python
versions 3.11+

## Using KubeRNP

Once installed, you can use KubeRNP in your Python projects:

```
from kubernp import KubeRNP

kubernp = KubeRNP()
kubernp.show_config()

exp = kubernp.create_experiment()
testweb = exp.create_deployment(name="testweb", image="nginx:latest", publish=[80])
testweb.cmd("echo '<h1>Hello World</h1>' > /var/www/index.html")
url = testweb.get_url()

import requests
requests.get(url).text
```
