#!/bin/bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' rossumxml-db-1