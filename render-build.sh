#!/usr/bin/env bash
# exit on error
set -o errexit

STORAGE_DIR=/opt/render/project/src/persistent

if [ ! -d "$STORAGE_DIR" ]; then
  echo "Creating persistent storage directory..."
  mkdir -p "$STORAGE_DIR"
fi

# Install Python dependencies
pip install -r requirements.txt

# Create directories for downloads/uploads
mkdir -p downloads
mkdir -p uploads

# Download and install FFmpeg static build (Fixed Extraction Method)
if [ ! -f "ffmpeg" ]; then
  echo "Downloading FFmpeg..."
  curl -L https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz -o ffmpeg.tar.xz
  
  # Create a temporary directory to extract safely
  mkdir -p ffmpeg_temp
  
  # Extract the entire archive into the temp folder
  tar -xf ffmpeg.tar.xz -C ffmpeg_temp
  
  # Move the ffmpeg binary to the root folder
  # The shell will handle the wildcard (*) expansion here, which is safer
  mv ffmpeg_temp/*/bin/ffmpeg .
  
  # Cleanup
  rm -rf ffmpeg_temp ffmpeg.tar.xz
  chmod +x ffmpeg
  echo "FFmpeg installed successfully."
else
  echo "FFmpeg already exists."
fi
