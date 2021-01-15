"""
Contains the actors in the 'Searching in the Dark' scheme described in the paper.
The actors includes:
    Data Owner
    Trusted Authority
    Cloud Service Provider
    Search User
"""
from typing import Tuple, List, Union
from pathlib import Path
import os.path
import logging
from omegaconf import DictConfig
from tqdm import tqdm

from database import insert_index_ta, insert_index_csp, \
    create_index_csp_table, create_index_ta_table, fetch_index_csp, \
    fetch_index_ta, select_index_ta_by_hashed_word, select_index_csp_by_addr_w, \
    update_addr_index_csp, increase_num_search_index_ta, decrease_index_ta_num_files, \
    delete_rows_index_ta, delete_rows_index_csp, change_addr_val_w_index_csp
from tools import DeterministicFernet, create_and_save_key, load_key, find_unique_words, \
    encrypt_file, decrypt_file, send_file, send_dir, hashing, get_cipher_from_key, \
    concat_strings, split_byte_strings

__all__ = ['DataOwner', 'TrustedAuthority', 'CloudServiceProvider', 'SearchUser']

# A logger for this file
log = logging.getLogger(__name__)


class DataOwner:
    """
    The data owner, who does most of the computing and heavy works.
    """
    def __init__(self, project_dir: str, cfg: DictConfig):
        self.verbose: bool = cfg.verbose
        self._get_paths(project_dir, cfg)
        self._key_gen()

    def _get_paths(self,
                   project_dir: Union[str, Path],
                   cfg: DictConfig) -> None:
        """
        Get the necessary paths.

        :param project_dir: the path to the directory of the project
        :param cfg:
        :return:
        """
        self.plaintext_dir: Path = Path(project_dir) / cfg.plaintext_dir
        if not self.plaintext_dir.exists():
            raise Exception(f"the plaintext dir {self.plaintext_dir} does not exist.")

        self.key_ta_path: Path = Path(project_dir) / 'data_owner/keys/key_ta.bin'
        self.key_ske_path: Path = Path(project_dir) / 'data_owner/keys/key_ske.bin'
        self.send_key_ta: Path = Path(project_dir) / 'trusted_authority/key_ta.bin'
        self.send_key_ta_search_user: Path = Path(project_dir) / 'search_user/key_ta.bin'
        self.send_key_ske_search_user: Path = Path(project_dir) / 'search_user/key_ske.bin'

        self.index_ta_path: Path = Path(project_dir) / 'data_owner/indexes/index_ta.db'
        self.index_csp_path: Path = Path(project_dir) / 'data_owner/indexes/index_csp.db'
        self.send_index_ta: Path = Path(project_dir) / 'trusted_authority/index_ta.db'
        self.send_index_csp: Path = Path(project_dir) / 'cloud_service_provider/index_csp.db'

        self.ciphertext_dir: Path = self.plaintext_dir.parent.parent/'ciphertexts'/self.plaintext_dir.name
        self.send_ciphertext_dir: Path = Path(project_dir)/'cloud_service_provider/ciphertexts'/self.plaintext_dir.name
        self.decrypted_dir: Path = Path(project_dir) / 'data_owner/decryptedtexts'

        if not self.ciphertext_dir.exists():
            self.ciphertext_dir.mkdir()

    def _key_gen(self) -> None:
        """
        The data owner generates the keys, if the keys already exist then he
        does not create a new key.
        key_ta is symmetric key shared with the Trusted Authority (TA).
        key_ske is the symmetric key used to encrypt the files, and is shared with other users
        that the data owner wants to share the files with.
        """
        if os.path.isfile(self.key_ta_path):
            log.info(f"(Data Owner key_gen) key_ta already exists at {self.key_ta_path}, no new key created.")
        else:
            self.key_ta: bytes = create_and_save_key(out_path=self.key_ta_path)
            log.info(f"(Data Owner key_gen) key_ta is saved to {self.key_ta_path}")
        if os.path.isfile(self.key_ske_path):
            log.info(f"(Data Owner key_gen) key_ske already exists at {self.key_ske_path}, no new key created.")
        else:
            self.key_ske: bytes = create_and_save_key(out_path=self.key_ske_path)
            log.info(f"(Data Owner key_gen) key_ske is saved to {self.key_ske_path}")

        self.key_ta: bytes = load_key(key_path=self.key_ta_path)
        self.key_ske: bytes = load_key(key_path=self.key_ske_path)
        log.info(f"(Data Owner key_gen) key_ske: {self.key_ske}, key_ta: {self.key_ta}")

        # make the ciphers based on the generated keys
        self.cipher_key_ta: DeterministicFernet = DeterministicFernet(self.key_ta)
        self.cipher_key_ske: DeterministicFernet = DeterministicFernet(self.key_ske)

        # send keys to the TA and the search user
        self.send_file(mode="key_ta", overwrite=False)
        self.send_file(mode="key_ske", overwrite=False)

    def send_file(self, mode: str,
                  overwrite: bool = True,
                  move_file: bool = False) -> None:
        """
        Send the key_ta to the TA.
        """
        mode_values: List[str] = ["key_ta", "key_ske", "index_ta", "index_csp"]
        assert mode in mode_values, "the parameter 'mode' should be " \
                                    "'key_ta', 'index_ta', 'index_csp', 'key_ske'"

        if mode == "key_ta":
            send_file(source=self.key_ta_path,
                      destination=self.send_key_ta,
                      overwrite=overwrite,
                      actor="Data Owner",
                      move_file=move_file)
            send_file(source=self.key_ta_path,
                      destination=self.send_key_ta_search_user,
                      overwrite=overwrite,
                      actor="Data Owner",
                      move_file=move_file)
        if mode == "key_ske":
            send_file(source=self.key_ske_path,
                      destination=self.send_key_ske_search_user,
                      overwrite=overwrite,
                      actor="Data Owner",
                      move_file=move_file)
        if mode == "index_ta":
            send_file(source=self.index_ta_path,
                      destination=self.send_index_ta,
                      overwrite=overwrite,
                      actor="Data Owner",
                      move_file=move_file)
        if mode == "index_csp":
            send_file(source=self.index_csp_path,
                      destination=self.send_index_csp,
                      overwrite=overwrite,
                      actor="Data Owner",
                      move_file=move_file)

    def send_dir(self, dir_name: str):
        """
        Send the directory to a destination.

        :return:
        """
        dir_values: List[str] = ["ciphertexts"]
        assert dir_name in dir_values, "the parameter 'dir' should be " \
                                       "'ciphertexts'"
        if dir_name == "ciphertexts":
            send_dir(source=self.ciphertext_dir,
                     destination=self.send_ciphertext_dir,
                     actor="Data Owner")

    def fetch_table(self, table: str, mode: str = "limit"):
        """
        Show rows in the tables.

        :param mode:
        :param table:
        :return:
        """
        table_values: List[str] = ["index_ta", "send_index_ta", "send_index_csp"]
        assert table in table_values, "the parameter 'table' should be one of " \
                                      "'index_ta', 'send_index_ta', 'send_index_csp'"
        if table == "index_ta":
            fetch_index_ta(index_ta_path=self.index_ta_path,
                           mode=mode,
                           actor="Data Owner")
        if table == "send_index_ta":
            fetch_index_ta(index_ta_path=self.send_index_ta,
                           mode=mode,
                           actor="Data Owner")
        if table == "send_index_csp":
            fetch_index_csp(index_csp_path=self.send_index_csp,
                            mode=mode,
                            actor="Data Owner")

    def get_csp_ciphertext_dir(self) -> Path:
        """
        Return the path to the CSP's ciphertext dir.
        :return:
        """
        return self.send_ciphertext_dir

    def _get_encrypted_indexes(self,
                               hashed_word: str,
                               num_of_search_w: int,
                               num_of_files_w: int,
                               file_name: str) \
            -> Tuple[bytes, str, bytes]:
        """
        Get k_w, addr_w, val_w.

        :param hashed_word:
        :param num_of_search_w:
        :param num_of_files_w:
        :param file_name:

        :return: k_w, addr_w, val_w
        """
        k_w_plaintext: bytes = concat_strings(hashed_word, str(num_of_search_w))
        k_w: bytes = self.cipher_key_ta.encrypt(k_w_plaintext)
        addr_w_plaintext: bytes = concat_strings(k_w.decode('utf-8'),
                                                 str(num_of_files_w), '0')
        addr_w: str = hashing(plaintext=addr_w_plaintext)
        val_w_plaintext: bytes = concat_strings(file_name, str(num_of_files_w))
        val_w: bytes = self.cipher_key_ske.encrypt(val_w_plaintext)

        return k_w, addr_w, val_w

    def index_gen(self):
        """
        The data owner creates the tables, generate the indexes required by the scheme.
        """
        if self.key_ta is None or self.key_ske is None:
            raise Exception("(Data Owner) key_ta or key_ske has not been generated")

        # create the tables needed to store the indexes
        create_index_ta_table(index_ta_path=self.index_ta_path, overwrite=True)
        create_index_csp_table(index_csp_path=self.index_csp_path, overwrite=True)

        files: List[Path] = sorted(Path(self.plaintext_dir).glob('*.txt'))
        # words_and_num_files: Counter = find_num_of_files(files_list=files)

        for i in tqdm(range(len(files))):
            self.add_file(file=files[i], mode="index_gen")
        log.info(f'(Data Owner index_gen) Indexing done, sending things to TA and CSP...')

        # data owner sends index_ta to TA
        self.send_file(mode="index_ta", overwrite=True)
        # data owner sends index_csp_path and encrypted files to CSP
        self.send_file(mode="index_csp", overwrite=True, move_file=True)
        self.send_dir(dir_name="ciphertexts")

    def add_file(self, file: Path,
                 mode: str = "add_file"):
        """
        Add a file to the encrypted database. Update the indexes.

        :param file: the path to the file to be added
        :param mode: either "add_file" (add a single file) or "index_gen" (used in index_gen function)
        :return:
        """
        mode_values: List[str] = ["add_file", "index_gen"]
        assert mode in mode_values, "the parameter mode should be " \
                                    "'add_file' or 'index_gen'"
        encrypted_filename: str = file.name
        encrypted_file_path: Path = self.ciphertext_dir / encrypted_filename
        if (self.send_ciphertext_dir/encrypted_filename).exists():
            raise Exception("(Data Owner add_file) The file you are adding has the same name with one of the "
                            "existing files in the database")

        unique_words: List = find_unique_words(file_path=file,
                                               sorted_list=True)

        for word in unique_words:
            word_in_byte: bytes = bytes(word, encoding='utf-8')
            hashed_word: str = hashing(plaintext=word_in_byte)
            matched_rows: List = select_index_ta_by_hashed_word(index_ta_path=self.index_ta_path,
                                                                hashed_word=hashed_word)
            if not matched_rows:  # empty list, new word
                num_of_files_w = 1
                num_of_search_w = 0
            else:
                _, _, num_of_files_w, num_of_search_w = matched_rows[-1]  # get the latest values
                num_of_files_w = num_of_files_w + 1

            k_w, addr_w, val_w = self._get_encrypted_indexes(hashed_word=hashed_word,
                                                             num_of_search_w=num_of_search_w,
                                                             num_of_files_w=num_of_files_w,
                                                             file_name=file.name)

            # add the values for each word to the data owner's tables
            data_ta: Tuple = (hashed_word, num_of_files_w, num_of_search_w)
            insert_index_ta(index_ta_path=self.index_ta_path,
                            data=data_ta)

            data_csp: Tuple = (addr_w, val_w)
            if mode == "index_gen":
                insert_index_csp(index_csp_path=self.index_csp_path,
                                 data=data_csp)

            if self.verbose:
                log.info(f"(Data Owner add_file) --- word | hashed | num files | num search | addr_w | val_w ---")
                log.info(f"(Data Owner add_file) {word} --- {hashed_word} --- {num_of_files_w} --- "
                         f"{num_of_search_w} --- {addr_w} --- {val_w}")

            if mode == "add_file":
                # send the data_csp to the CSP and data_ta to the TA
                if self.verbose:
                    log.info(f'(Data Owner add_file) send {data_csp} to CSP,\n and {data_ta} to the TA. '
                             f'\nThen they update their tables.')
                insert_index_csp(index_csp_path=self.send_index_csp,
                                 data=data_csp)
                insert_index_ta(index_ta_path=self.send_index_ta,
                                data=data_ta)

        encrypt_file(input_path=file,
                     output_path=encrypted_file_path,
                     cipher=self.cipher_key_ske)

        if mode == "add_file":
            # send the encrypted file to the CSP
            send_file(source=encrypted_file_path,
                      destination=self.send_ciphertext_dir/encrypted_filename,
                      overwrite=True,
                      actor="Data Owner add_file")

    def increase_num_of_search(self, csp_acknowledgement: bool, hashed_search_word: str) -> None:
        """
        Increase the num_of_search of the searched word.

        :return:
        """
        if not csp_acknowledgement:
            return
        matched_rows: List[Tuple] = select_index_ta_by_hashed_word(index_ta_path=self.index_ta_path,
                                                                   hashed_word=hashed_search_word)
        for row in matched_rows:
            row_id, hashed_word, num_files, num_searches = row
            increase_num_search_index_ta(index_ta_path=self.index_ta_path,
                                         new_num_searches=num_searches+1,
                                         row_id=row_id)
            if self.verbose:
                log.info(f'(Data Owner increase_num_of_search) updating index_ta at '
                         f'row {row_id} with new num_search_w = {num_searches+1}')

    def _get_addr_w(self,
                    hashed_word: str,
                    num_files_w: int,
                    num_search_w: str) -> str:
        """

        :param hashed_word:
        :param num_files_w:
        :param num_search_w:
        :return: addr_w: the address value in the index_csp table.
        """
        k_w_plaintext: bytes = concat_strings(hashed_word, str(num_search_w))
        k_w: bytes = self.cipher_key_ta.encrypt(k_w_plaintext)
        addr_w_plaintext: bytes = concat_strings(k_w.decode('utf-8'), str(num_files_w), '0')
        addr_w: str = hashing(plaintext=addr_w_plaintext)

        return addr_w

    def _get_val_w_by_addr_w(self,
                             addr_w: str) -> bytes:
        """
        Find the corresponding val_w in the index_csp table for a corresponding add_w

        :param addr_w:
        :return:
        """
        row_index_csp: List = select_index_csp_by_addr_w(index_csp_path=self.send_index_csp, addr_w=addr_w)
        _, _, val_w = row_index_csp[-1]

        return val_w

    def _get_file_names_num_files(self,
                                  hashed_word: str,
                                  indexes_ta_w: List[Tuple] = None) -> List[Tuple[str, int]]:
        """
        Given a hashed word, find and return all the file names and the number of files of that word,
        which is encoded in the val_w value.

        :param hashed_word
        :param indexes_ta_w:
        :return:
        """
        if indexes_ta_w is None:
            indexes_ta_w = select_index_ta_by_hashed_word(index_ta_path=self.index_ta_path,
                                                          hashed_word=hashed_word)
        result: List[Tuple[str, int]] = []
        for row_id, hashed_word, num_files_w, num_searches_w in indexes_ta_w:
            addr_w = self._get_addr_w(hashed_word=hashed_word,
                                      num_files_w=num_files_w,
                                      num_search_w=num_searches_w)
            row_index_csp: List = select_index_csp_by_addr_w(index_csp_path=self.send_index_csp, addr_w=addr_w)
            row_id, old_addr_w, val_w = row_index_csp[-1]
            assert addr_w == old_addr_w, "2 values of addr_w should be the same"
            val_w_plaintext: bytes = self.cipher_key_ske.decrypt(val_w)
            file_name, num_files = split_byte_strings(val_w_plaintext)
            result.append((file_name, int(num_files)))

        return result

    def _delete_file_name_decrease_num_files(self,
                                             file_names_num_files: List[Tuple[str, int]],
                                             delete_file_name: str) -> List[Tuple[str, int]]:
        """
        Delete the file name from the list of file names and number of files,
        decrease the number of files by 1 for the remaining entries.

        :param file_names_num_files: the list of tuples that contains the file
                                    names and the corresponding number of files.
        :param delete_file_name: the file name to be deleted
        :return:
        """
        file_names_num_files.sort(key=lambda x: x[1])  # sort the list based on the second values of the tuples
        delete_index: int = [i for i, k in enumerate(file_names_num_files) if k[0] == delete_file_name][0]
        # decrease the num_files values by one for the entries with indexes bigger than the delete_index
        decreased_num_files: List[Tuple[str, int]] = [(k[0], k[1]-1) if (i > delete_index) else
                                                      (k[0], k[1]) for i, k in enumerate(file_names_num_files)]
        remain_file_names_num_files: List[Tuple[str, int]] = [my_tuple for my_tuple in decreased_num_files
                                                              if my_tuple[0] != delete_file_name]
        return remain_file_names_num_files

    def _choose_file_name_by_num_file(self,
                                      file_names_num_files: List[Tuple[str, int]],
                                      num_file: int) -> str:
        """
        Choose the proper file name based on the num_file

        :param file_names_num_files: the list of tuples that contains the file
                                    names and the corresponding number of files.
        :param num_file: the num of file where the corresponding file name will be returned.
        :return: the corresponding file name of num_file in file_names_num_files
        """
        return [my_tuple[0] for my_tuple in file_names_num_files if my_tuple[1] == num_file][0]

    def delete(self,
               delete_file_path: Path) \
            -> Tuple[str, List[Tuple[str, int]], List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]]]:
        """
        The data owner deletes an encrypted file from her collection on the CSP's database.

        :param delete_file_path: the path to the file to be deleted
        :return: delete_file_name: the name of the deleted file.
                 file_number (List[Tuple[str, int]]): the list containing the hashed word and their number of files
                            in the deleted file.
                 delete_tokens (List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]]): contains the old addr_w, old val_w
                            which will be replaced by the corresponding new add_w, val_w values in the index_csp table.
        """
        if not delete_file_path.exists():
            raise Exception(f"(Data Owner delete) the file {delete_file_path} does not exist. Do nothing.")
        log.info(f"(Data Owner delete) Deleting file {delete_file_path}")

        delete_file_name: str = delete_file_path.name
        decrypted_file_path: Path = self.decrypted_dir/delete_file_path.name
        decrypt_file(input_path=delete_file_path,
                     output_path=decrypted_file_path,
                     cipher=self.cipher_key_ske)

        file_number: List[Tuple[str, int]] = []
        delete_tokens: List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]] = []

        unique_words: List[str] = find_unique_words(decrypted_file_path, sorted_list=True)
        for word in unique_words:
            hashed_word: str = hashing(word)
            indexes_ta_w: List[Tuple] = select_index_ta_by_hashed_word(index_ta_path=self.index_ta_path,
                                                                       hashed_word=hashed_word)
            file_names_num_files: List[Tuple[str, int]] = self._get_file_names_num_files(hashed_word=hashed_word,
                                                                                         indexes_ta_w=indexes_ta_w)
            remain_file_names_decreased_num_files = self._delete_file_name_decrease_num_files(file_names_num_files,
                                                                                              delete_file_name)
            for row_id, hashed_word, num_files_w, num_searches_w in indexes_ta_w:
                old_addr_w: str = self._get_addr_w(hashed_word=hashed_word,
                                                   num_files_w=num_files_w,
                                                   num_search_w=num_searches_w)
                old_val_w: bytes = self._get_val_w_by_addr_w(addr_w=old_addr_w)
                old_file_name, old_num_file = split_byte_strings(self.cipher_key_ske.decrypt(old_val_w))
                assert int(old_num_file) == num_files_w, "num_files_w getting from index_ta " \
                                                         "and from index_csp are different"

                if num_files_w > 1:
                    new_num_files_w = num_files_w - 1
                    new_file_name: str = self._choose_file_name_by_num_file(remain_file_names_decreased_num_files,
                                                                            num_file=new_num_files_w)
                    _, new_addr_w, new_val_w = self._get_encrypted_indexes(hashed_word=hashed_word,
                                                                           num_of_search_w=num_searches_w,
                                                                           num_of_files_w=new_num_files_w,
                                                                           file_name=new_file_name)
                    if self.verbose:
                        log.info(f"(Data Owner delete) index_ta: update from "
                                 f"({row_id} | {word} | {hashed_word} | {num_files_w} | {num_searches_w}) "
                                 f"new_num_file: {new_num_files_w}, "
                                 f"index_csp will be updated at "
                                 f"({row_id} | old addr_w {old_addr_w} (hash({word}), {num_searches_w}, {num_files_w}) "
                                 f"| old val_w {old_val_w} ({old_file_name}, {old_num_file})"
                                 f"to new_addr_w {new_addr_w} (hash({word}), {num_searches_w}, {new_num_files_w})"
                                 f" and new val_w {new_val_w} ({new_file_name}, {new_num_files_w})")
                else:
                    new_addr_w = '0'
                    new_val_w = b'0'
                    if self.verbose:
                        log.info(f"This row (id={row_id} of word {word}) will be deleted")

                file_number.append((hashed_word, num_files_w))  # this will be sent to the TA
                delete_tokens.append(((old_addr_w, new_addr_w), (old_val_w, new_val_w)))  # will be sent to the CSP

        self._update_index_ta_after_delete(delete_file_name=delete_file_name,
                                           file_number=file_number)

        return delete_file_name, file_number, delete_tokens

    def _update_index_ta_after_delete(self,
                                      delete_file_name: str,
                                      file_number: List[Tuple[str, int]]) -> None:
        """
        The data owner updates his index_ta table after deleting a file. Used in the delete() function.

        :param delete_file_name: the name of the deleted file.
        :param file_number: the list containing the hashed word and their number of files
                            in the deleted file.
        :return:
        """
        log.info(f"(Data Owner) Update the index_ta table after deleting the file {delete_file_name}")
        delete_rows = [my_tuple for my_tuple in file_number if my_tuple[1] == 1]
        decrease_num_files_rows = [my_tuple for my_tuple in file_number if my_tuple[1] > 1]
        assert len(delete_rows) + len(decrease_num_files_rows) == len(file_number), \
            "the sum of the lengths of the rows to be deleted and rows where num files will be decreased" \
            "is not the same with the length of file_number"
        delete_rows_index_ta(index_ta_path=self.index_ta_path,
                             delete_rows=delete_rows)
        decrease_index_ta_num_files(index_ta_path=self.index_ta_path,
                                    rows=decrease_num_files_rows)


class SearchUser:
    """
    Class represents a user trying to search for files in the database.
    """
    def __init__(self,
                 project_dir: str,
                 cfg: DictConfig,
                 csp_ciphertext_dir: Path,
                 search_word: str):
        self.verbose: bool = cfg.verbose

        self.search_word: bytes = bytes(search_word, encoding="utf-8")
        self.hashed_search_word: str = self.hash_search_word()

        self.key_ta_path: Path = Path(project_dir) / 'search_user/key_ta.bin'
        self.key_ske_path: Path = Path(project_dir) / 'search_user/key_ske.bin'
        self.csp_ciphertext_dir: Path = csp_ciphertext_dir
        self.decrypttext_dir: Path = Path(project_dir) / 'search_user/decrypted'
        if not self.decrypttext_dir.exists():
            self.decrypttext_dir.mkdir()

        self.cipher_key_ta: DeterministicFernet = get_cipher_from_key(key_path=self.key_ta_path)
        self.cipher_key_ske: DeterministicFernet = get_cipher_from_key(key_path=self.key_ske_path)

    def hash_search_word(self) -> str:
        """
        Hash and return the hashed search word.
        :return: the hashed word.
        """
        hashed_word: str = hashing(plaintext=self.search_word)
        return hashed_word

    def create_search_token(self, search_word_indexes: List) \
            -> Tuple[bytes, int, List]:
        """

        :param search_word_indexes: the List that contains the matched rows of the hashed
                search word received from the TA.
        :return:
        """
        _, _, num_of_files_w, num_of_search_w = search_word_indexes[-1]
        k_w_plaintext: bytes = concat_strings(self.hashed_search_word, str(num_of_search_w))
        k_w: bytes = self.cipher_key_ta.encrypt(k_w_plaintext)

        new_num_of_search_w = num_of_search_w + 1
        new_k_w_plaintext: bytes = concat_strings(self.hashed_search_word, str(new_num_of_search_w))
        new_k_w: bytes = self.cipher_key_ta.encrypt(new_k_w_plaintext)

        if self.verbose:
            log.info(f"(Search User create_search_token) K'_w (plaintext) --- K'_w (ciphertext)")
            log.info(f"{new_k_w_plaintext} --- {new_k_w}")

        l_u: List = []
        for i in range(1, num_of_files_w+1):
            addr_w_plaintext: bytes = concat_strings(new_k_w.decode('utf-8'), str(i), '0')
            addr_w: str = hashing(plaintext=addr_w_plaintext)
            l_u.append(addr_w)

        return k_w, num_of_files_w, l_u

    def verify_and_retrieve_encrypted_files(self, encrypted_file_names: List[bytes]):
        """
        Decrypt the encrypted files got from the CSP.

        :param encrypted_file_names:
        :return:
        """

        for cf in encrypted_file_names:
            val_w_plaintext: bytes = self.cipher_key_ske.decrypt(cf)
            file_name, num_files = split_byte_strings(val_w_plaintext)
            decrypted_file_path: Path = self.decrypttext_dir/file_name
            decrypt_file(input_path=self.csp_ciphertext_dir/file_name,
                         output_path=decrypted_file_path,
                         cipher=self.cipher_key_ske)
            log.info(f"(Search User verify_and_retrieve_encrypted_files) the decrypted file(s) "
                     f"for the word {self.search_word.decode('utf-8')} is saved to {decrypted_file_path}")


class TrustedAuthority:
    """
    Class represents the trusted authority (TA).
    """
    def __init__(self,
                 project_dir: str,
                 cfg: DictConfig):

        self.verbose: bool = cfg.verbose
        self.index_ta: Path = Path(project_dir) / 'trusted_authority/index_ta.db'
        self.key_ta: Path = Path(project_dir) / 'trusted_authority/key_ta.bin'
        self.cipher_key_ta: DeterministicFernet = get_cipher_from_key(key_path=self.key_ta)

    def send_indexes_by_hashed_word(self, hashed_search_word: str):
        """
        Assumes that the user requesting the hashed search word is verified.
        TA searches her database, return the num_of_files and num_of_search for the
        corresponding hashed word. She also sends her key to the search user.

        :param hashed_search_word: the hashed word
        :return:
        """
        matched_rows: List[Tuple] = select_index_ta_by_hashed_word(index_ta_path=self.index_ta,
                                                                   hashed_word=hashed_search_word)
        return matched_rows

    def create_check_list(self, k_w: bytes, num_of_files_w: int) \
            -> List[str]:
        """
        Create the check list La that would be sent to the CSP.

        :param k_w:
        :param num_of_files_w:
        :return:
        """
        k_w_decrypted: bytes = self.cipher_key_ta.decrypt(k_w)
        hashed_word, num_of_search_w = split_byte_strings(k_w_decrypted)

        new_num_of_search_w = int(num_of_search_w) + 1
        new_k_w_plaintext: bytes = concat_strings(hashed_word, str(new_num_of_search_w))
        new_k_w: bytes = self.cipher_key_ta.encrypt(new_k_w_plaintext)

        if self.verbose:
            log.info(f"(TA create_check_list) K'_w (plaintext) --- K'_w (ciphertext): ")
            log.info(f"{new_k_w_plaintext} --- {new_k_w}")

        l_ta: List[str] = []
        for i in range(1, num_of_files_w+1):
            addr_w_plaintext: bytes = concat_strings(new_k_w.decode('utf-8'), str(i), '0')
            addr_w: str = hashing(plaintext=addr_w_plaintext)
            l_ta.append(addr_w)

        return l_ta

    def increase_num_of_search(self, csp_acknowledgement: bool, hashed_search_word: str) -> None:
        """
        Increase the num_of_search of the searched word.

        :return:
        """
        if not csp_acknowledgement:
            return
        matched_rows: List[Tuple] = select_index_ta_by_hashed_word(index_ta_path=self.index_ta,
                                                                   hashed_word=hashed_search_word)
        for row in matched_rows:
            row_id, hashed_word, num_files, num_searches = row
            increase_num_search_index_ta(index_ta_path=self.index_ta,
                                         new_num_searches=num_searches+1,
                                         row_id=row_id)
            if self.verbose:
                log.info(f'(TA increase_num_of_search) updating index_ta at row {row_id} with new'
                         f'num searches of {num_searches+1}')

    def fetch_table(self):
        """
        Fetch the index_ta's table
        :return:
        """
        fetch_index_ta(index_ta_path=self.index_ta,
                       mode="all")

    def update_index_ta_after_user_delete_file(self,
                                               delete_file_name: str,
                                               file_number: List[Tuple[str, int]]) -> None:
        """
        The data owner updates his index_ta table after deleting a file. Used in the delete() function.

        :param delete_file_name: the name of the deleted file.
        :param file_number: the list containing the hashed word and their number of files
                            in the deleted file.
        :return:
        """
        log.info(f"(TA) Update the index_ta table after data owner deletes the file {delete_file_name}")
        delete_rows = [my_tuple for my_tuple in file_number if my_tuple[1] == 1]
        decrease_num_files_rows = [my_tuple for my_tuple in file_number if my_tuple[1] > 1]
        assert len(delete_rows) + len(decrease_num_files_rows) == len(file_number), \
            "the sum of the lengths of the rows to be deleted and rows where num files will be decreased" \
            "is not the same with the length of file_number"
        delete_rows_index_ta(index_ta_path=self.index_ta,
                             delete_rows=delete_rows)
        decrease_index_ta_num_files(index_ta_path=self.index_ta,
                                    rows=decrease_num_files_rows)


class CloudServiceProvider:
    """
    Class represents the Cloud Service Provider (CSP).
    """
    def __init__(self,
                 project_dir: str,
                 cfg: DictConfig,
                 ciphertext_dir: Path):
        self.verbose: bool = cfg.verbose
        self.index_csp_path: Path = Path(project_dir) / 'cloud_service_provider/index_csp.db'
        self.ciphertext_dir: Path = ciphertext_dir

    def verify_check_lists(self, l_u: List[str],
                           l_ta: List[str], k_w: bytes,
                           num_of_files_w: int) -> Tuple[List[bytes], bool]:
        """

        :param l_u:
        :param l_ta:
        :param k_w:
        :param num_of_files_w:
        :return:
        """
        if sorted(l_u) == sorted(l_ta):
            log.info('(CSP verify_check_lists) l_u and l_ta are equal, proceeding.')
        else:
            raise Exception('(CSP verify_check_lists) l_u and l_ta are not equal, aborting the protocol!')

        encrypted_file_names: List[bytes] = []
        for i in range(1, num_of_files_w+1):
            addr_w_plaintext: bytes = concat_strings(k_w.decode('utf-8'), str(i), '0')
            addr_w: str = hashing(plaintext=addr_w_plaintext)
            matched_row: List = select_index_csp_by_addr_w(index_csp_path=self.index_csp_path,
                                                           addr_w=addr_w)
            if len(matched_row) == 0:
                log.info(f"(CSP verify_check_lists) No results found based on K_w {k_w}, "
                         f"something is wrong!")
                return [], False

            row_id, old_addr_w, val_w = matched_row[-1]
            encrypted_file_names.append(val_w)

            if self.verbose:
                log.info(f"(CSP verify_check_lists) updating index_csp table at row"
                         f" {row_id}, replacing old addr_w {old_addr_w} with {l_u[i-1]}")
            update_addr_index_csp(index_csp_path=self.index_csp_path,
                                  new_addr=l_u[i-1],
                                  row_id=row_id)
        csp_acknowledgement: bool = True

        return encrypted_file_names, csp_acknowledgement

    def fetch_table(self):
        fetch_index_csp(index_csp_path=self.index_csp_path,
                        actor="CSP",
                        mode="all")

    def update_index_csp_after_user_delete_file(self,
                                                delete_file_name: str,
                                                delete_tokens: List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]]) \
            -> None:
        """
        CSP updates index_csp after deleting file.

        :param delete_file_name: the name of the deleted file.
        :param delete_tokens: contains the old addr_w, old val_w
                              which will be replaced by the corresponding new add_w,
                              val_w values in the index_csp table.
        :return:
        """
        log.info(f"(CSP) Update the index_csp table after data owner deletes the file {delete_file_name}")

        delete_rows: List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]] = []
        change_values_rows: List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]] = []
        for token in delete_tokens:
            if token[0][1] == '0':
                delete_rows.append(token)
            else:
                change_values_rows.append(token)
        assert len(delete_rows) + len(change_values_rows) == len(delete_tokens), \
            "the sum of the lengths of the rows to be deleted and rows where the values will be changed" \
            "is not the same with the length of delete_tokens"
        delete_rows_index_csp(index_csp_path=self.index_csp_path,
                              delete_rows=delete_rows)
        change_addr_val_w_index_csp(index_csp_path=self.index_csp_path,
                                    rows=change_values_rows)

    def delete_file(self, delete_file_path: Path):
        """
        Delete the file with path given by 'delete_file_path'.

        :param delete_file_path:
        :return:
        """
        log.info(f"(CSP) remove the file {delete_file_path}")
        delete_file_path.unlink()
