#!/bin/sh
# One-command reproduction of the whole chain, to be run INSIDE the container:
#
#   docker build -t sakana-nested-name-or-path <this folder>
#   docker run --rm -it -v "<this folder>:/work" sakana-nested-name-or-path bash
#   sh reproduce.sh
#
# The same commands, one by one, are what the screenshots show (see
# ../截图与复现指引.md for the command-to-screenshot table).
set -e

echo "### 1. build the model packages"
python make_poc.py

echo
echo "### 2. no payload has run yet"
python check_marker.py

echo
echo "### 3. control: the nested field points at an ordinary config"
python victim_load.py work/control/model-A-control
python check_marker.py

echo
echo "### 4. attack: the nested field points at the repository that carries the payload"
python victim_load.py work/attacker/model-A-evil
python check_marker.py

echo
echo "### 5. remote variant: the same field holding a real Hub repository id"
python victim_config_only.py work/hub/model-A-hub

echo
echo "### 6. cleanup"
rm -f /tmp/sakana_nested_name_or_path_marker
python check_marker.py
