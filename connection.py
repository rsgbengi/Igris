import os
import shutil

actual_dir = os.getcwd()
output_dir = "/home/rsgbengi/Igris/meh"
try:
    os.rename(f"{actual_dir}/cosa.txt", f"{output_dir}/cosa.txt")
    os.replace(f"{actual_dir}/cosa.txt", f"{output_dir}/cosa.txt")
    shutil.move(f"{actual_dir}/cosa.txt", f"{output_dir}/cosa.txt")
except FileNotFoundError:
    print("File or directory target for sam hashes not found")
