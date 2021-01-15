"""
Contains the code for the 4 algorithms described in the paper: index generation, file insertion, search, delete.
"""
from typing import List
import logging
from pathlib import Path
from omegaconf import DictConfig
import time

from searching_in_the_dark import DataOwner, SearchUser, \
    TrustedAuthority, CloudServiceProvider

from tools import logging_time

# A logger for this file
log = logging.getLogger(__name__)


def indexing(cfg: DictConfig, project_dir: str):
    """
    Generates the index databases (index_ta and index_csp) that contains the
    hashed words, the number of files containing those words, the number of times
    each word has been searched by a user, the mapping of a keyword and the file names.
    index_ta is copied to the TA.
    index_csp is moved to the CSP (data owner does not keep index_csp.db after indexing is done).

    :param cfg: the DictConfig object that is built from the config.yaml file
    :param project_dir: the path of the project
    :return:
    """
    log.info(f"------------------------- Indexing -------------------------")
    start_indexing_time: float = time.time()
    data_owner = DataOwner(project_dir=project_dir, cfg=cfg.data_owner)
    # data owner creates the tables, generates the indexes required by the scheme
    data_owner.index_gen()
    end_indexing_time: float = time.time()
    logging_time(start_indexing_time, end_indexing_time, 'indexing')

    # show the created tables
    if cfg.data_owner.verbose:
        data_owner.fetch_table(table="index_ta", mode="all")
        data_owner.fetch_table(table="send_index_csp", mode="all")


def file_insertion(cfg: DictConfig, project_dir: str):
    """
    The data owner add a new file to her encrypted collection on the cloud and updates all the indexes accordingly.

    :param cfg: the DictConfig object that is built from the config.yaml file
    :param project_dir: the path of the project
    :return:
    """
    # data owner generates the keys
    log.info(f"------------------------- File Insertion -------------------------")
    start_insertion_time: float = time.time()
    data_owner = DataOwner(project_dir=project_dir, cfg=cfg.data_owner)
    data_owner.add_file(file=Path(project_dir)/cfg.data_owner.add_file)
    end_insertion_time: float = time.time()
    logging_time(start_insertion_time, end_insertion_time, 'file insertion')

    if cfg.data_owner.verbose:
        data_owner.fetch_table(table="index_ta", mode="all")
        data_owner.fetch_table(table="send_index_ta", mode="all")
        data_owner.fetch_table(table="send_index_csp", mode="all")


def search(cfg: DictConfig, project_dir: str, search_word: str):
    """
    A search user searches for the files that contain a search key word in the encrypted database on the cloud.
    The data owner shares with the search user his secret key and trusted authority case (secure? can be improved?).
    All corresponding indexes are updated.

    :param cfg: the DictConfig object that is built from the config.yaml file
    :param project_dir: the path of the project
    :param search_word: the word to search
    :return:
    """
    log.info(f"------------------------- Searching -------------------------")
    start_searching_time: float = time.time()
    data_owner = DataOwner(project_dir=project_dir, cfg=cfg.data_owner)
    csp_ciphertext_dir: Path = data_owner.get_csp_ciphertext_dir()
    search_user = SearchUser(project_dir=project_dir,
                             cfg=cfg.search_user,
                             csp_ciphertext_dir=csp_ciphertext_dir,
                             search_word=search_word)
    hashed_search_word: str = search_user.hash_search_word()
    log.info(f"Search User is searching for the word "
             f"{search_word} with hash {hashed_search_word}")

    ta = TrustedAuthority(project_dir=project_dir, cfg=cfg.trusted_authority)
    matched_rows: List = ta.send_indexes_by_hashed_word(hashed_search_word=hashed_search_word)
    if len(matched_rows) == 0:
        log.info(f'(TA) can not find any results for {search_word}, '
                 f'aborting search.')
    else:
        log.info(f"(Search User) creating search token (K_w, No.Files_w, L_u), send to CSP")
        k_w, num_of_files_w, l_u = search_user.create_search_token(search_word_indexes=matched_rows)

        log.info(f"(TA) creating the check list (L_ta), send it to CSP")
        l_ta: List[str] = ta.create_check_list(k_w=k_w,
                                               num_of_files_w=num_of_files_w)

        log.info(f"(CSP) verify if L_ta and L_u are the same, then send the "
                 f"encrypted file names to the search user.")
        csp = CloudServiceProvider(project_dir=project_dir,
                                   cfg=cfg.cloud_service_provider,
                                   ciphertext_dir=csp_ciphertext_dir)
        encrypted_file_names, csp_acknowledgement = csp.verify_check_lists(l_u=l_u,
                                                                           l_ta=l_ta,
                                                                           k_w=k_w,
                                                                           num_of_files_w=num_of_files_w)

        if csp_acknowledgement:
            log.info(f"(Search User) Decrypt the files, and save them.")
            search_user.verify_and_retrieve_encrypted_files(encrypted_file_names)
            log.info(f"(Data Owner and TA) Increase the number of searches for the "
                     f"searched word.")
            data_owner.increase_num_of_search(csp_acknowledgement, hashed_search_word)
            ta.increase_num_of_search(csp_acknowledgement, hashed_search_word)

    end_searching_time: float = time.time()
    logging_time(start_searching_time, end_searching_time, 'searching')


def delete(cfg: DictConfig, project_dir: str):
    """
    The data owner deletes a file from the encrypted database and updates all the indexes accordingly.

    :param cfg: the DictConfig object that is built from the config.yaml file
    :param project_dir: the path of the project
    :return:
    """
    log.info(f"------------------------- Delete -------------------------")
    start_delete_time: float = time.time()

    data_owner = DataOwner(project_dir=project_dir, cfg=cfg.data_owner)
    if cfg.data_owner.verbose:
        log.info("(Data Owner) Fetching index_ta table BEFORE delete rows and decrease num files")
        data_owner.fetch_table(table="index_ta", mode="all")
    csp_ciphertext_dir: Path = data_owner.get_csp_ciphertext_dir()
    delete_file_path: Path = Path(project_dir)/cfg.data_owner.delete_file
    deleted_file_name, file_number, delete_tokens = data_owner.delete(delete_file_path)
    if cfg.data_owner.verbose:
        log.info("(Data Owner) Fetching index_ta table AFTER delete rows and decrease num files")
        data_owner.fetch_table(table="index_ta", mode="all")

    ta = TrustedAuthority(project_dir=project_dir, cfg=cfg.trusted_authority)
    if cfg.trusted_authority.verbose:
        log.info("(TA) Fetching index_ta table BEFORE delete rows and decrease num files")
        ta.fetch_table()
    ta.update_index_ta_after_user_delete_file(delete_file_name=deleted_file_name,
                                              file_number=file_number)
    if cfg.trusted_authority.verbose:
        log.info("(TA) Fetching index_ta table AFTER delete rows and decrease num files")
        ta.fetch_table()

    csp = CloudServiceProvider(project_dir=project_dir,
                               cfg=cfg.cloud_service_provider,
                               ciphertext_dir=csp_ciphertext_dir)
    if cfg.cloud_service_provider.verbose:
        log.info("(CSP) Fetching index_csp table BEFORE delete rows and decrease num files")
        csp.fetch_table()
    csp.update_index_csp_after_user_delete_file(delete_file_name=deleted_file_name,
                                                delete_tokens=delete_tokens)
    if cfg.cloud_service_provider.verbose:
        log.info("(CSP) Fetching index_csp table AFTER delete rows and decrease num files")
        csp.fetch_table()
    csp.delete_file(delete_file_path)

    end_delete_time: float = time.time()
    logging_time(end_delete_time, start_delete_time, 'delete')
