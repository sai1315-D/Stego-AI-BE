import os
import sys
import urllib.request
import zipfile
import shutil

def download_and_setup():
    url = "https://oliverbetz.de/cms/files/Artikel/ExifTool-for-Windows/exiftool-13.59_64.zip"
    dest_zip = "exiftool.zip"
    backend_dir = r"d:\project\stego AI\backend"
    
    print(f"Downloading ExifTool from {url}...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as response, open(dest_zip, 'wb') as out_file:
        out_file.write(response.read())
    print("Download completed.")
    
    print("Extracting archive...")
    with zipfile.ZipFile(dest_zip, 'r') as zip_ref:
        zip_ref.extractall("exiftool_temp")
    
    print("Moving files to backend directory...")
    # Find exiftool(-k).exe
    exe_name = "exiftool(-k).exe"
    temp_exe_path = os.path.join("exiftool_temp", exe_name)
    target_exe_path = os.path.join(backend_dir, "exiftool.exe")
    
    if os.path.exists(temp_exe_path):
        shutil.copy(temp_exe_path, target_exe_path)
        print(f"Copied and renamed executable to {target_exe_path}")
    else:
        # Check if there is another .exe
        for f in os.listdir("exiftool_temp"):
            if f.endswith(".exe"):
                shutil.copy(os.path.join("exiftool_temp", f), target_exe_path)
                print(f"Copied {f} to {target_exe_path}")
                break
                
    # Check for exiftool_files directory
    temp_files_dir = os.path.join("exiftool_temp", "exiftool_files")
    target_files_dir = os.path.join(backend_dir, "exiftool_files")
    if os.path.exists(temp_files_dir):
        if os.path.exists(target_files_dir):
            shutil.rmtree(target_files_dir)
        shutil.copytree(temp_files_dir, target_files_dir)
        print(f"Copied exiftool_files to {target_files_dir}")
        
    # Cleanup
    os.remove(dest_zip)
    shutil.rmtree("exiftool_temp")
    print("Setup completed successfully.")

if __name__ == "__main__":
    download_and_setup()
