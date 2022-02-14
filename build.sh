#!/bin/bash

mkdir build
cd build
cmake -D DEBUG=1 ..
make
