import requests
import os
import sys

virustotal_uri = "https://virusshare.com/hashfiles/VirusShare_"
existing_hashes = []

if __name__ == "__main__":
  
  directory = "existing_hashes"
  path = os.path.join(os.path.dirname(os.path.realpath(__file__)),directory)

  if not os.path.isdir(path):
    os.mkdir(path)
  
  existing_hashes = os.listdir(path)
  existing_hashes = [f.lower() for f in existing_hashes]
  existing_hashes = sorted(existing_hashes)

  if len(existing_hashes) < 1:
    print('* Downloading first hash file...')
    url = virustotal_uri+"00000.md5"
    r = requests.get(url)

    print(f'Status Code: {r.status_code}')

    if r.status_code == 200:
      with open(path+'/hash_00000.md5', 'wb') as f:
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
      with open(path+'/hash_'+next_hash+'.md5', 'wb') as f:
        f.write(r.content)
      print(f'Downloaded {next_hash}.')
    else:
      print('Hashes up-to-date.')
      break