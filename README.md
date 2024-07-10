# Introduction
This program is to send your exported csv from local spiderfoot to elasticsearch

# Requirement

## Install Pip and library
First, install pip 
* in ubuntu:

    `sudo apt install python3-pip`
* in centos:

    `yum install python3-pip`

then install requirements with pip
* in linux:

    `pip install -r requirements.txt`

* in windows:

    `python3 -m pip install -r requirements.txt`

# Running
copy `fim_config.yaml.example` into `fim_config.yaml` and fill the config, then run:

    `python3 main.py`