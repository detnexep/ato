#!/bin/bash

# Install Python packages
pip install selenium==4.7.0
pip install requests==2.28.2

# Download and install Geckodriver
wget https://github.com/mozilla/geckodriver/releases/download/v0.31.0/geckodriver-v0.31.0-linux64.tar.gz
tar -xvzf geckodriver-v0.31.0-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/

# Verify installation
geckodriver --version
