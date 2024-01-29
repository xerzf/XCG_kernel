#!/bin/bash

sudo make INSTALL_MOD_STRIP=1 modules_install -j$(nproc)
sudo make install
