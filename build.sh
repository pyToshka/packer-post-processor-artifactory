#!/usr/bin/env bash
cd example
go get github.com/pyToshka/packer-post-processor-artifactory
packer build packer.json