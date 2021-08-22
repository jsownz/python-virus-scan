import requests
import os
import sys
import hashlib
import argparse
from multiprocessing import Process
from timeit import default_timer as timer

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# set up args
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", dest="directory_to_scan", help="Full path to scan")
    options = parser.parse_args()
    if not options.directory_to_scan:
        # handle error
        parser.error(f"{bcolors.FAIL}[-] Please specify a directory to scan, use --help for more info{bcolors.ENDC}")
    return options
 
# Using VirusShare md5 hash database, thank you for your research: https://virusshare.com
virusshare_uri = "https://virusshare.com/hashfiles/VirusShare_"
hash_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)),'existing_hashes')
infected_hashes = []
hashed_files = {}
options = get_arguments()

# Update the hashes
def update_hashes():
  if not os.path.isdir(hash_directory):
    os.mkdir(hash_directory)
  
  existing_hashes = os.listdir(hash_directory)
  existing_hashes = [f.lower() for f in existing_hashes]
  existing_hashes = sorted(existing_hashes)

  if len(existing_hashes) < 1:
    print(f'{bcolors.OKGREEN}* Downloading first hash file...{bcolors.ENDC}')
    url = virusshare_uri+"00000.md5"
    r = requests.get(url)

    if r.status_code == 200:
      with open(hash_directory+'/hash_00000.md5', 'wb') as f:
        f.write(r.content)

  last_hashfile = existing_hashes[-1]
  last_hash_file_number = int(last_hashfile.split("_")[1].split('.')[0])
  next_hash_file_number = last_hash_file_number + 1

  print(f'{bcolors.OKCYAN}Checking for new hashes...{bcolors.ENDC}')

  recent_hash = str(last_hash_file_number).zfill(5)
  url = virusshare_uri+recent_hash+".md5"
  r = requests.get(url)

  if r.status_code == 200:
    with open(hash_directory+'/hash_'+recent_hash+'.md5', 'wb') as f:
      f.write(r.content)

  for i in range(next_hash_file_number,10000):
    next_hash = str(i).zfill(5)
    url = virusshare_uri+next_hash+".md5"
    r = requests.get(url)

    if r.status_code == 200:
      with open(hash_directory+'/hash_'+next_hash+'.md5', 'wb') as f:
        f.write(r.content)
      print(f'Downloaded {next_hash}.')
    else:
      print(f'{bcolors.OKGREEN}Hashes up-to-date.{bcolors.ENDC}')
      break

# Compare a hash         
def compare_hash(hash,counter):
  match = False
  existing_hashes = os.listdir(hash_directory)
  for file in existing_hashes:
    f = open(hash_directory+'/'+file, "r")
    readfile = f.read()
    if hash in readfile:
      match = True
      print(f"{bcolors.FAIL}Infected File: {hashed_files[hash]}{bcolors.ENDC}")
      infected_hashes.append(hash)
      f.close()
      continue
    else:
      f.close()

  if not match:
    print(f'{counter}/{len(hashed_files)} Scanned.', end='\r')

# Loop through hashed files and start a process to check the hash
def compare_hashes(hashed_files):
  counter = 1
  for hash in hashed_files:
    p = Process(target=compare_hash, args=(hash,counter))
    p.start()
    counter += 1

# Recurse through the directory if it contains directories
def recurse_and_hash(filename, file):
  if os.path.isfile(filename):
    hashed_file = hashlib.md5(open(filename,'rb').read()).hexdigest()
    hashed_files[hashed_file] = filename
  else:
    child_files = files_to_hash = os.listdir(filename)
    for child_file in child_files:
      child_filename = filename+'/'+child_file
      recurse_and_hash(child_filename, child_file)

# Kick off the scan of the directory to get files and hash them
def scan_directory(directory_to_scan):
  print(f'Scanning Directory: {directory_to_scan}...')
  files_to_hash = os.listdir(directory_to_scan)

  for file in files_to_hash:
    filename = directory_to_scan+'/'+file
    recurse_and_hash(filename, file)

  print(f'Scanning {len(hashed_files)} files...')
  compare_hashes(hashed_files)

if __name__ == "__main__":
  
  try:
    update_hashes()

    # directory_to_scan = os.path.realpath('/home/jason/Documents')
    start = timer()
    p1 = Process(target=scan_directory, args=(options.directory_to_scan,))
    p1.start()
    p1.join()
    end = timer()
    print(f'Completed in {end - start} seconds.')

    print('Scan Complete.')
    if len(infected_hashes) > 0:
      print('Infections found:')
      for hash in infected_hashes:
        print(f'Hash: {hash}')

  except KeyboardInterrupt:
    print("")
    print('Scan Interrupted.')
    if len(infected_hashes) > 0:
      print('Infections found:')
      for hash in infected_hashes:
        print(hashed_files[hash])
    sys.exit(0)
