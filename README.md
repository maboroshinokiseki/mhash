# Description
A simple file hashing tool similar to RHash.
It can utilize multiple cores to speed up hashing process if you're hashing multiple files or doing multiple hashes at the same time.

# Supported hashes
CRC32, CRC32C, MD2, MD4, MD5, SHA1, SHA2, SHA3

# Usage
check SFV files
```
mhash -c /path_of_the_file 
```

get sha1 hashes of a single file.
```
mhash --sha1 /path_of_the_file 
```

get sha1 hashes of files in a folder recursively.
```
mhash --sha1 -r /path_of_the_folder 
```

for more usage, just check mhash --help