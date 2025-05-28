#!/bin/bash

# Make sure docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    echo "https://docs.docker.com/engine/install/"
    echo "Make sure to add your user to the docker group or run this script with sudo."
    exit 1
fi

# Check if in virtual environment
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "You are not in a virtual environment."
    echo "Do you want to create a virtual environment? (y/n)"
    read -r create_venv
    if [[ "$create_venv" == "y" ]]; then
        python3 -m venv .venv
        source .venv/bin/activate
        echo "Virtual environment created and activated."
    else
        echo "Please activate a virtual environment before running this script."
        exit 1
    fi
fi

# Install dependencies
pip install -r requirements.txt
if [[ $? -ne 0 ]]; then
    echo "Failed to install dependencies. Please check the requirements.txt file."
    exit 1
fi

# Build the Docker image
wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v3.1.0.tar.gz
if [[ $? -ne 0 ]]; then
    echo "Failed to download binwalk. Please check your internet connection."
    exit 1
fi
tar -xzf v3.1.0.tar.gz
if [[ $? -ne 0 ]]; then
    echo "Failed to extract binwalk. Please check the downloaded file."
    exit 1
fi

cd binwalk-3.1.0 || exit 1
docker build -t binwalkv3 .

if [[ $? -ne 0 ]]; then
    echo "Failed to build the Docker image. Please check the Dockerfile."
    exit 1
fi
echo "Docker image 'binwalkv3' built successfully."

# Clean up
cd ..
rm -rf binwalk-3.1.0 v3.1.0.tar.gz
echo "Cleaned up temporary files."
echo "Installation complete"