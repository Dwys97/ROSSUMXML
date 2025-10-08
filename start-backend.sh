#!/bin/bash
cd backend
sam local start-api --port 3000 --docker-network rossumxml_default
