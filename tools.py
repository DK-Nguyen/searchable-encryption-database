"""
Utility functions and classes.
"""
from typing import Union, List, TextIO
from pathlib import Path
from shutil import copyfile, copytree, rmtree, move
from omegaconf import DictConfig
import os
import re
import logging
from collections import Counter

from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from cryptography.fernet import Fernet


# A logger for this file
log = logging.getLogger(__name__)


def reset(cfg: DictConfig, project_dir: str):
    """
    Delete the directories and files, reset the project for the new run.

    :return:
    """
    for i, k in enumerate(cfg):
        if k != "data_owner":
            actor_dir: Path = Path(project_dir) / k
            if actor_dir.exists():
                rmtree(actor_dir)
                log.info(f'(main) remove directory {actor_dir}')
        else:
            data_owner_indexes_dir: Path = (Path(project_dir) / 'data_owner/indexes')
            data_owner_keys_dir: Path = (Path(project_dir) / 'data_owner/keys')
            data_owner_ciphertext_dir: Path = (Path(project_dir) / 'data_owner/ciphertexts')
            data_owner_decryptedtext_dir: Path = (Path(project_dir) / 'data_owner/decryptedtexts')
            dirs = [data_owner_indexes_dir, data_owner_keys_dir,
                    data_owner_ciphertext_dir, data_owner_decryptedtext_dir]
            for d in dirs:
                if d.exists():
                    rmtree(d)
                    log.info(f'(main) remove directory {d}')


def create_actors(cfg: DictConfig, project_dir: str):
    """
    Create the actors according to the configs, make the necessary directories
    for the scheme.

    :param cfg:
    :param project_dir:
    :return:
    """
    for i, k in enumerate(cfg):
        if k != "data_owner":
            actor_dir: Path = Path(project_dir) / k
            if not actor_dir.exists():
                actor_dir.mkdir()
                log.info(f'(main) create directory {actor_dir}')

    data_owner_indexes_dir: Path = (Path(project_dir)/'data_owner/indexes')
    data_owner_keys_dir: Path = (Path(project_dir)/'data_owner/keys')
    data_owner_ciphertext_dir: Path = (Path(project_dir)/'data_owner/ciphertexts')
    data_owner_decryptedtext_dir: Path = (Path(project_dir) / 'data_owner/decryptedtexts')
    dirs = [data_owner_indexes_dir, data_owner_keys_dir,
            data_owner_ciphertext_dir, data_owner_decryptedtext_dir]
    for d in dirs:
        if not d.exists():
            d.mkdir()
            log.info(f'(main) create directory {d}')


class DeterministicFernet(Fernet):
    """
    Inherits from Fernet but produces the same ciphertexts for the same
    plaintexts (this is insecure).
    """
    def __init__(self, key):
        super(DeterministicFernet, self).__init__(key)

    def encrypt(self, data: bytes) -> bytes:
        iv: bytes = b'\xdd\xc7\xfdV%\x04r]\xd3\x87\xb2?_\xf6\x83\x19'
        current_time = 0
        return self._encrypt_from_parts(data, current_time, iv)


def create_and_save_key(out_path: Union[str, Path]) -> bytes:
    """
    Create the key for Fernet, and then save to the out_path.
    :return:
    """
    key: bytes = DeterministicFernet.generate_key()
    # save the keys
    file_out = open(out_path, "wb")
    file_out.write(key)
    file_out.close()
    return key


def load_key(key_path: Path) -> bytes:
    """
    Load the existing key.
    :param key_path: the Path object containing the path to the key.
    :return: the key in bytes
    """
    key_file = open(key_path, "rb")
    key: bytes = key_file.read()
    key_file.close()
    return key


def send_file(source: Union[str, Path],
              destination: Union[str, Path],
              overwrite: bool = True,
              actor: str = "",
              move_file: bool = False) -> None:
    """
    Send a file from source to destination

    :param source: the path indicates the source file
    :param destination: the path indicates the destination file
    :param overwrite: if True, then overwrite the destination file if it already exists.
    :param actor: the actor that does this action
    :param move_file: if this is true, then move instead of copy
    """
    if os.path.isfile(destination):
        if not overwrite:
            log.info(f"({actor}) {destination} already exist, do not send.")
            return

    if move_file:
        move(src=source, dst=destination)
        log.info(f"({actor}) {source.name} is moved to {destination}.")
    else:
        copyfile(src=source, dst=destination)
        log.info(f"({actor}) {source.name} is copied to {destination}.")


def send_dir(source: Union[str, Path],
             destination: Union[str, Path],
             actor: str = "") -> None:
    """
    Send a directory from source to destination. Always overwrite if the destination
    dir already exists.

    :param source: the path indicates the source directory
    :param destination: the path indicates the destination directory
    :param actor:
    """
    if type(source) == str:
        source = Path(source)
    if type(destination) == str:
        destination = Path(destination)
    if not destination.parent.exists():
        destination.parent.mkdir()
    if destination.exists():
        rmtree(destination)

    copytree(source, destination)
    log.info(f"({actor}) {source} dir is sent to {destination}.")


def find_unique_words(file_path: Path,
                      sorted_list: bool = False) -> List:
    """
    Find the list of all unique words in a file given by file_path.
    :param file_path: the path to the file.
    :param sorted_list: if true, then return the sorted list.
    :return:
    """
    f: TextIO = open(file_path, "r")
    strings: str = f.read()
    words: List = re.findall(pattern=r'\w+', string=strings)
    if sorted_list:
        unique_words: List = sorted(list(set(words)))
    else:
        unique_words: List = list(set(words))

    return unique_words


def encrypt_file(input_path: Union[str, Path],
                 output_path: Union[str, Path],
                 cipher: DeterministicFernet) -> None:
    """
    Given a input_path (str or Path object) and the cipher, it encrypts the
    file and write it to the path given by the output_path.

    :param input_path
    :param output_path
    :param cipher
    """
    # if os.path.isfile(output_path):
    #     log.info(f"{output_path} already exist, do nothing.")
    #     return
    with open(input_path, "rb") as file:
        file_data = file.read()
    encrypted_data: bytes = cipher.encrypt(file_data)
    with open(output_path, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(input_path: Union[str, Path],
                 output_path: Union[str, Path],
                 cipher: DeterministicFernet) -> None:
    """
    Given a input_path (str or Path object) and the cipher, it decrypts the
    file and write it to the path given by the output_path.

    :param input_path
    :param output_path
    :param cipher
    """
    # if os.path.isfile(output_path):
    #     log.info(f"{output_path} already exist, do nothing.")
    #     return
    with open(input_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data: bytes = cipher.decrypt(encrypted_data)
    with open(output_path, "wb") as file:
        file.write(decrypted_data)


def find_num_of_files(files_list: List[Path]) -> Counter:
    """
    Loop through all the files in the file_list, find all the unique words in each file.
    Then count the number of files a unique word can be found.

    :param files_list:
    :return: a counter object that keeps the number of files where a unique word could be found.
    """
    words_all_files: List = []
    for file in files_list:
        f: TextIO = open(file, "r")
        strings: str = f.read()
        words: List = re.findall(pattern=r'\w+', string=strings)
        unique_words: List = list(set(words))
        words_all_files.extend(unique_words)

    return Counter(words_all_files)


def hashing(plaintext: Union[bytes, str]) -> str:
    """
    Hash a word.

    :param plaintext: the plaintext in bytes
    :return: the hashed word.
    """
    if type(plaintext) == str:
        to_be_hashed: bytes = bytes(plaintext, encoding='utf-8')
    else:
        to_be_hashed = plaintext

    hash_func: SHA256Hash = SHA256.new()
    hash_func.update(to_be_hashed)
    hashed_word: str = hash_func.hexdigest()

    return hashed_word


def get_cipher_from_key(key_path: Union[str, Path]) -> DeterministicFernet:
    """
    Get the Fernet cipher based on the key provided by key_path

    :param key_path:
    :return:
    """
    key_file = open(key_path, "rb")
    key: bytes = key_file.read()
    cipher = DeterministicFernet(key)
    key_file.close()

    return cipher


def concat_strings(*strings: str, delimiter: str = ' ') \
        -> bytes:
    """
    Concatenating multiple strings and return the byte
    array of the resulting string encoded in utf-8.

    :param strings: strings that will be concatenated
    :param delimiter:
    :return: the byte array of the concatenated string
    """
    result = delimiter.join([s for s in strings])
    return bytes(result, encoding='utf-8')


def split_byte_strings(byte_string: bytes, delimiter: str = ' ') \
        -> List[str]:
    """

    :param byte_string:
    :param delimiter:
    :return:
    """
    strings: str = byte_string.decode('utf-8')
    str_parts: List = strings.split(delimiter)

    return str_parts


def get_bool_input_from_user(operation: str):
    """
    Get the input in True or False from the user, if true, then proceed to do the operation.
    :param operation: the name of the operation
    :return:
    """
    proceed = input(f"(enter y or n) Do {operation}?")
    if proceed == "y":
        return True
    elif proceed == "n":
        return False
    else:
        raise Exception("Type in only 'y' or 'n'. Don't mess with me!")


def get_user_input():
    """
    Get the input in integers from the user.

    :return:
    """
    try:
        user_input = int(input("Enter 1 to reset, 2 to do indexing, 3 to do file insertion, \n"
                               "4 to search a word, 5 to delete a file, 6 to show all tables, \n"
                               "and 7 to quit: \n"))
    except ValueError:
        user_input = 0

    if int(user_input) not in range(1, 8):
        log.info("The input needs to be numbers from 1-7")
        user_input = 0

    return user_input


def logging_time(start_time: float, end_time: float, operation: str):
    hours, rem = divmod(end_time - start_time, 3600)
    minutes, seconds = divmod(rem, 60)
    log.info("{} takes {:0>2}:{:0>2}:{:05.2f}".format(operation, int(hours), int(minutes), seconds))
