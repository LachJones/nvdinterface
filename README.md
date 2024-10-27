# NVDClient

NVDClient is a python library to simplify retrieving and interacting with data from the National Vulnerability Database (NVD).

This project is currently in the early stages of development and will hopefully see changes soon, however is being made available early for others to use, test, and request changes on.

---

## Install

```shell
(.venv) $ pip install nvdclient
```


## Example Usage

```pycon
>>> from nvdclient import search_cves
>>> search_cves(cveId="CVE-2021-44228")
```

## Building from Source

1. Clone the repository
2. Enter repository directory
3. Install using poetry

*Example:*

```shell
(.venv) $ git clone https://github.com/LachJones/nvdclient.git
(.venv) $ cd nvdclient
(.venv) $ python -m poetry install
```