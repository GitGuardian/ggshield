#! /usr/bin/env bash

args=("$@")
ggshield secret scan -v ${args[@]} ci
