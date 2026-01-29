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

# Create directories for downloads/uploads to prevent errors
mkdir -p downloads
mkdir -p uploads

# Download and install FFmpeg static build
if [ ! -f "ffmpeg" ]; then
  echo "Downloading FFmpeg..."
  curl -L https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz -o ffmpeg.tar.xz
  tar -xf ffmpeg.tar.xz --strip-components=2 */bin/ffmpeg
  rm ffmpeg.tar.xz
  chmod +x ffmpeg
  echo "FFmpeg installed."
else
  echo "FFmpeg already exists."
fi