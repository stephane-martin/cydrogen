#!/bin/fish
# exexute the develop session but abort if error occurs
nox -s develop || exit 1
# activate the virtual environment
source .nox/develop/bin/activate.fish
# start a fish shell within the virtual environment
exec fish
