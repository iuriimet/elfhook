#!/bin/bash

#gbs --conf gbs/gbs_tizen6.5.conf build -P tizen -A i586 --spec=elfhook.spec --incremental --clean --include-all
gbs --conf gbs/gbs_tizen6.5.conf build -P tizen6.5 -A i586 --incremental --clean --include-all
