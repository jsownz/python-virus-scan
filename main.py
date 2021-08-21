import requests
import os
import sys
import hashlib

virustotal_uri = "https://virusshare.com/hashfiles/VirusShare_"
hash_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)),'existing_hashes')
infected_hashes = []

def update_hashes():
  if not os.path.isdir(hash_directory):
    os.mkdir(hash_directory)
  
  existing_hashes = os.listdir(hash_directory)
  existing_hashes = [f.lower() for f in existing_hashes]
  existing_hashes = sorted(existing_hashes)

  if len(existing_hashes) < 1:
    print('* Downloading first hash file...')
    url = virustotal_uri+"00000.md5"
    r = requests.get(url)

    print(f'Status Code: {r.status_code}')

    if r.status_code == 200:
      with open(hash_directory+'/hash_00000.md5', 'wb') as f:
        f.write(r.content)

  last_hashfile = existing_hashes[-1]
  last_hash_file_number = int(last_hashfile.split("_")[1].split('.')[0])
  next_hash_file_number = last_hash_file_number + 1

  print('Checking for new hashes...')

  for i in range(next_hash_file_number,10000):
    next_hash = str(i).zfill(5)
    url = virustotal_uri+next_hash+".md5"
    r = requests.get(url)

    if r.status_code == 200:
      with open(hash_directory+'/hash_'+next_hash+'.md5', 'wb') as f:
        f.write(r.content)
      print(f'Downloaded {next_hash}.')
    else:
      print('Hashes up-to-date.')
      break

def compare_hash(hash):
  match = False
  existing_hashes = os.listdir(hash_directory)
  print(f'Checking hash {hash}')

  file_counter = 1
  for file in existing_hashes:
    with open(hash_directory+'/'+file) as lines:
      for line in lines:
        line = line.strip()
        print(f'({round((file_counter/len(existing_hashes))*100)}%) {line}', end='\r')
        if line == hash:
          match = True
          print(f'Found one: {hash}')
          infected_hashes.append(hash)
          break
      else:
        file_counter += 1
        continue
      break

  if not match:
    print(f'{hash} Clean!')

def compare_hashes(hashed_files):
  counter = 1
  for hash in hashed_files:
    print(f'Hash {counter}/{len(hashed_files)}...')
    compare_hash(hash)
    counter += 1

def scan_directory(directory_to_scan):
  print(f'Scanning Directory: {directory_to_scan}...')
  files_to_hash = os.listdir(directory_to_scan)
  hashed_files = []

  for file in files_to_hash:
    filename = directory_to_scan+'/'+file
    hashed_file = hashlib.md5(open(filename,'rb').read()).hexdigest()
    hashed_files.append(hashed_file)
  compare_hashes(hashed_files)

if __name__ == "__main__":
  
  try:
    update_hashes()

    directory_to_scan = os.path.realpath('/home/jason/Documents')

    scan_directory(directory_to_scan)

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
        print(f'Hash: {hash}')
    sys.exit(0)
