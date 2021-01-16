# Symmetric searchable encryption database 
An implementation of a searchable encryption database with forward privacy, according to 
the paper [Power Range: Forward Private Multi-Client Symmetric Searchable Encryption with 
Range Queries Support](https://ieeexplore.ieee.org/abstract/document/9219739) [Alexandros Bakas, Antonis Michalas].

## Requirements:
python >= 3.7 \
cryptography=3.1.1 \
hydra-core=1.0.4 \
pycryptodome=3.9.8 \
tqdm=4.55.1

Automatically install necessary packages using conda: run
```conda create --name <envname> --file requirements.yaml```. 

## Scheme
The figure below shows the tables that contain the indexes of the encrypted database, which are generated
by the indexing algorithm. These tables are updated accordingly when the data owner add a file to the
database, search a word, or delete a file. Please refer to the paper to see how they are done.

![Figure 1](tables.png)

## Project structure
Note: * indicates that a directory/file is created automatically after running.

```.
├── data_owner              # holds the plaintexts, and creates all the necessary keys and indexes, then send them
│   ├── plaintexts
│   │    ├── E               # debugging dataset
│   │    ├── A               # contains debugging text files to be added in the file_insertion algorithm
│   │    ├── D10             # contains 10 text files from the real dataset (https://zenodo.org/record/3360392)
│   │    ├── D10_A           # contains the text files to be added to the encrypted collection in the file_insertion algorithm
│   │    ├── D25
│   │    ├── D25_A
│   ├── ciphertexts*         # the encrypted data from plaintexts, will be sent to the cloud service provider (CSP)
│   ├── decryptedtexts*      # used to debug
│   ├── keys*                 
│   │    ├── key_ske.bin*    # the key used to encrypt the datasets, can be shared with search user
│   │    ├── key_ta.bin*     # the key shared with the trusted authority 
│   └── indexes*
│        ├── index_ta.db*    # the data owner keeps this table and updates along side with the TA
│        ├── index_csp.db*   # this will be moved to cloud_service_provider after indexing 
├── cloud_service_provider*  # contains the ciphertexts and index_csp table
|       ├── ciphertexts*     
|       ├── index_csp.db*    
├── trusted_authority*       
|       ├── index_ta.db*    
|       ├── key_ta.bin*    
├── search_user*             # represents a user who wants to search the encrypted database 
|       ├── decrypted*       # the decrypted files that contains the searched keywords
|       ├── key_ske.bin*     # shared by the data_owner
|       ├── key_ta.bin*      # shared by the data_owner
├── outputs*                 # all the logs are saved to corresponding directories of each run
├── config.yaml             # the paths to plaintext directory, the files to be added/deleted are set here
├── requirements.yaml       
├── main.py                 # run this file 
├── processes.py            # together with searching_in_the_dark.py, this file implements the algorithms of the scheme 
├── searching_in_the_dark.py
├── database.py             # code that handle the database
└── tools.py                # utility functions
 ```

When proper configurations are configured in the ```config.yaml```, the user can run ```python main.py```.
Note that if the content of the file `config.yaml` is changed when the program is running, 
you need to quit it and run again.
There are several options that could be chosen from:
- 1: if the user enters 1, the old automatically created directories, e.g. cloud_service_provider, trusted_authority, 
  and search_user will be removed, and the new empty ones will be created.
  The new keys are generated and sent to the proper actors.
- 2: run the indexing algorithm, based on the value of `data_owner.plaintext_dir` in `config.yaml`.
- 3: run the file insertion algorithm, based on the value of `data_owner.add_file` in `config.yaml`.
- 4: search for files that contain a word entered by the user.
- 5: delete a file, based on the value of `data_owner.delete_file` in `config.yaml`. 
- 6: show all tables. 
- 7: quit:.
After each run, all the logs will be saved to the file ```main.log``` in the automatically created
directory ```output/<time_running>/```.

