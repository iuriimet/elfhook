#!/bin/bash

mkdir build
cd build
cmake -D RELEASE=1 ..
make
