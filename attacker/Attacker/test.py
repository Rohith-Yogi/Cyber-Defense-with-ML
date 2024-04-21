import subprocess
import os
import zipfile
import shutil
import pyminizip



def build():
    # Path to vcvarsall.bat
    # vcvars_path = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvarsall.bat"

    # Architecture (e.g., "amd64", "x86")
    architecture = "amd64"

    # Path to MSBuild.exe
    msbuild_path = "msbuild"

    # Path to your solution file
    solution_path = os.path.join(os.path.dirname(__file__), 'Attacker.vcxproj')

    # Build configuration (e.g., "Release" or "Debug")
    build_config = "Release"

    # Set up the environment
    # subprocess.call(['cmd', '/c', vcvars_path, architecture])

    # Build the project
    subprocess.call([msbuild_path, solution_path, "/t:Rebuild", f"/p:Configuration={build_config}", "/p:UseEnv=true"])


# def compress_directory(input_dir, output_zip, password=None):
#     # try:
#     # Get a list of all files and subdirectories in the input directory
#     file_list = []
#     prefixes = []
#     for root, dirs, files in os.walk(input_dir):
#         for file in files:
#             file_path = os.path.join(root, file)
#             file_list.append(file_path)
#             prefixes.append(input_dir)
#
#     print(file_list)
#
#     # Compress the directory into a ZIP file
#     # pyminizip.compress_multiple(file_list, prefixes, output_zip, password, 0)
#     # subprocess.run(['7z', 'a', f'-p{password}', 'output', input_dir], check=True)
#
#
#     print(f'Directory "{input_dir}" compressed into "{output_zip}" successfully.')
#
#     # except Exception as e:
#     #     print(f'Error occurred: {e}')

def main():
    print(f'Executing in path: {os.path.dirname(__file__)}')

    dropper_path = os.path.join(os.path.dirname(__file__), 'Release', 'Attacker.exe')
    malwares_path = os.path.join(os.path.dirname(__file__), 'malware-samples', 'evade_me_2024.zip')
    droppers_path = os.path.join(os.path.dirname(__file__), 'droppers')
    pwd = b'infected'
    extract_path = os.path.join(os.path.dirname(__file__), 'malware-file', 'malware.bin')

    try:
        if os.path.exists(os.path.join(os.path.dirname(__file__), 'Release')) == False:
            os.mkdir(os.path.join(os.path.dirname(__file__), 'Release'))

        if os.path.exists(os.path.join(os.path.dirname(__file__), 'malware-file')) == False:
            os.mkdir(os.path.join(os.path.dirname(__file__), 'malware-file'))

    except Exception as e:
        print(f'Unable to create folders: {e}')

    try:
        if os.path.exists(droppers_path):
            shutil.rmtree(droppers_path)

        os.mkdir(droppers_path)

        with zipfile.ZipFile(malwares_path, 'r') as zip:
            for info in zip.infolist():
                if not info.is_dir():
                    bytez = zip.read(info.filename, pwd=pwd)
                    with open(extract_path, 'wb') as malware_file:
                        malware_file.write(bytez)

                    build()

                    with open(dropper_path, 'rb') as dropper:
                        with open(os.path.join(droppers_path, info.filename.split('/')[-1]), 'wb') as dropper_file:
                            dropper_file.write(dropper.read())

        # compress_directory(droppers_path, os.path.join(os.path.dirname(__file__), 'droppers.zip'), password=pwd)
        # shutil.rmtree(droppers_path)

        print("################### SUCCESSS ###################")

    except Exception as e:
        os.remove(os.path.join(os.path.dirname(__file__), 'droppers.zip'))
        print(f'Exception Occured: {e}')
    finally:
        shutil.rmtree(os.path.join(os.path.dirname(__file__), 'Release'))
        shutil.rmtree(os.path.join(os.path.dirname(__file__), 'malware-file'))
    

if __name__ == '__main__':
    main()







