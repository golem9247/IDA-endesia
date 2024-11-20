#env python3
import shutil
import platform
import os
import pathlib
import subprocess

FILES = ["endesia-plugin.py", "libendesia"]

def install_files():

    idapro_plugins_path = os.path.join(os.environ['HOME'], ".idapro", "plugins")
    if not os.path.exists(idapro_plugins_path):
        os.system(f"mkdir -p {idapro_plugins_path}")

    for file in FILES:
        file_dst = os.path.join(idapro_plugins_path, file)
        if os.path.exists(file_dst):
            if os.path.isdir(file_dst):
                shutil.rmtree(file_dst)
            else:
                os.unlink(file_dst)

        parent = pathlib.Path(__file__).parent
        file_src = os.path.join(parent, file)

        if os.path.isdir(file_src):
            shutil.copytree(file_src, file_dst)
        else:
            shutil.copy(file_src, file_dst)

        print(f"Copied {file} to {file_dst} : OK")

    
def main():

    if platform.system() != "Linux":
        raise Exception("Unsuported")

    install_files()

if __name__ == "__main__":
    main()
