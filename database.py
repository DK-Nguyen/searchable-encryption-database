"""
Code that handles the databases.
"""

import sqlite3
from sqlite3 import Error, Connection, Cursor
import os
from typing import Union, Tuple, List
from pathlib import Path
import logging

# A logger for this file
log = logging.getLogger(__name__)


def create_connection(db_path: Union[str, Path]) -> Union[None, Connection]:
    """
    Create a database connection to a SQLite database

    :param db_path: the path to the database (*.db)
    """
    conn = None
    try:
        conn: Connection = sqlite3.connect(db_path)
        return conn
    except Error as e:
        log.error(e)

    return conn


def create_table(conn: Connection, create_table_sql: str):
    """
    Create a table from the create_table_sql statement

    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c: Cursor = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        log.error(e)


def create_index_ta_table(index_ta_path: Union[str, Path],
                          overwrite: bool = False) -> None:
    """
    Create the database that contains the indexes that would be sent to the Trusted Authority (TA)
    """
    if os.path.isfile(index_ta_path):
        if not overwrite:
            log.info(f"{index_ta_path} already exist, do nothing.")
            return
        else:
            log.info(f"{index_ta_path} already exist, removing and creating a new database.")
            index_ta_path.unlink()

    conn: Connection = create_connection(index_ta_path)
    sql = """ CREATE TABLE IF NOT EXISTS index_ta (
              keywords_id integer PRIMARY KEY,
              keyword TEXT,
              keyword_numfiles integer,
              keyword_numsearch integer
           ); """
    if conn is not None:
        create_table(conn, sql)
    else:
        log.error("Error! cannot create the database connection.")


def create_index_csp_table(index_csp_path: Union[str, Path],
                           overwrite: bool = False) -> None:
    """
    Create the database that contains the indexes that would be sent to the Cloud Service Provider (CSP)

    :param index_csp_path: the path to the index_csp_path database
    :param overwrite
    """
    if os.path.isfile(index_csp_path):
        if not overwrite:
            log.info(f"{index_csp_path} already exist, do nothing.")
            return
        else:
            log.info(f"{index_csp_path} already exist, removing and creating a new database.")
            index_csp_path.unlink()

    conn = create_connection(index_csp_path)
    sql = """ CREATE TABLE IF NOT EXISTS index_csp (
              csp_keywords_id integer PRIMARY KEY,
              csp_keywords_address text,
              csp_keywords_value text
          ); """
    if conn is not None:
        create_table(conn, sql)
    else:
        log.error("Error! cannot create the database connection.")


def insert_index_ta(index_ta_path: Union[str, Path], data: Tuple) -> int:
    """
    Insert data into the index_ta table

    :param index_ta_path:
    :param data: a row of data to be inserted to the table
    :return: project id
    """
    conn: Connection = create_connection(index_ta_path)
    sql: str = ''' INSERT INTO index_ta(keyword,keyword_numfiles,keyword_numsearch)
              VALUES(?,?,?) '''
    cur: Cursor = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
    return cur.lastrowid


def insert_index_csp(index_csp_path: Union[str, Path], data: Tuple) -> int:
    """
    Insert data into the index_csp_path table

    :param index_csp_path: the path to the index_csp_path database
    :param data: a row of data to be inserted to the table
    :return: project id
    """
    conn: Connection = create_connection(index_csp_path)
    sql: str = ''' INSERT INTO index_csp(csp_keywords_address,csp_keywords_value)
              VALUES(?,?) '''
    cur: Cursor = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
    return cur.lastrowid


def fetch_index_ta(index_ta_path: Union[str, Path],
                   mode: str = "limit",
                   actor: str = "") -> None:
    """
    Select all the data in the index_ta table and log them out.

    :return:
    """
    conn: Connection = create_connection(index_ta_path)
    cur: Cursor = conn.cursor()
    if mode == "limit":
        cur.execute('SELECT * from index_ta '
                    'ORDER BY keywords_id DESC '
                    'LIMIT 10')
    else:
        cur.execute('SELECT * from index_ta '
                    'ORDER BY keywords_id DESC ')

    names: List = [description[0] for description in cur.description]
    rows: List = cur.fetchall()
    log.info(f'({actor}) Fetching table {index_ta_path}: {names}')
    for row in rows:
        log.info(row)


def fetch_index_csp(index_csp_path: Union[str, Path],
                    mode: str = "limit",
                    actor: str = "") -> None:
    """
    Select all the data in the index_ta table and log them out.
    :param index_csp_path: the path to the index_csp table.
    :param mode: "all" or "limit"
    :param actor: the actor that does this action
    :return:
    """
    conn: Connection = create_connection(index_csp_path)
    cur: Cursor = conn.cursor()
    if mode == "limit":
        cur.execute('SELECT * from index_csp '
                    'ORDER BY csp_keywords_id DESC '
                    'LIMIT 10')
    else:
        cur.execute('SELECT * from index_csp '
                    'ORDER BY csp_keywords_id DESC')

    names: List = [description[0] for description in cur.description]
    rows: List = cur.fetchall()
    log.info(f'({actor}) Fetching table {index_csp_path}: {names}')
    for row in rows:
        log.info(row)


def select_index_ta_by_hashed_word(index_ta_path: Union[str, Path],
                                   hashed_word: str) -> List[Tuple]:
    """
    Find and return a row in the index_ta table based on the hashed word

    :param hashed_word:
    :param index_ta_path: the path to the index_ta database
    :return: the list of rows that have the hashed word as key word.
    """
    conn: Connection = create_connection(index_ta_path)
    cur: Cursor = conn.cursor()
    cur.execute("SELECT * FROM index_ta WHERE keyword=?", (hashed_word,))
    rows: List[Tuple] = cur.fetchall()
    # log.info(f' Selecting based on hashed word {hashed_word}, results: ')
    # for row in rows:
    #     log.info(row)

    return rows


def select_index_csp_by_addr_w(index_csp_path: Union[str, Path],
                               addr_w: str) -> List:
    """
    Find and return a row in the index_ta table based on the hashed word

    :param index_csp_path: the path to the csp database
    :param addr_w: the csp_keywords_address (a hash value)

    :return: the list of rows that have the addr_w.
    """
    conn: Connection = create_connection(index_csp_path)
    cur: Cursor = conn.cursor()
    cur.execute("SELECT * FROM index_csp WHERE csp_keywords_address=?", (addr_w,))
    rows: List = cur.fetchall()
    assert len(rows) == 1 or len(rows) == 0, \
        "There should be no matched rows, or only 1 matched row," \
        "as addr_w should be unique"

    return rows


def select_index_csp_by_id(index_csp_path: Path,
                           row_id: int) -> Tuple:
    """
    Find and return a row in the index_ta table based on the hashed word

    :param index_csp_path: the path to the csp database
    :param row_id: the csp_keywords_address (a hash value)
    :return: the list of rows that have the addr_w.
    """
    conn: Connection = create_connection(index_csp_path)
    cur: Cursor = conn.cursor()
    cur.execute("SELECT * FROM index_csp WHERE csp_keywords_id=?", (row_id,))
    row: List = cur.fetchall()

    return row[0]


def compare_two_db(db1: Union[str, Path],
                   db2: Union[str, Path],
                   mode: str = Union["index_ta", "index_csp"]) -> set:
    """
    Comparing 2 databases

    :param mode:
    :param db1:
    :param db2:
    :return:
    """
    conn = sqlite3.connect(db1)
    conn.execute("ATTACH ? AS db2", [str(db2)])
    res1 = None
    res2 = None
    if mode == "index_csp":
        res1 = conn.execute("""SELECT * FROM main.index_csp
                               WHERE csp_keywords_id NOT IN
                             (SELECT csp_keywords_id FROM db2.index_csp)
                            """).fetchall()
        res2 = conn.execute("""SELECT * FROM db2.index_csp
                               WHERE csp_keywords_id NOT IN
                             (SELECT csp_keywords_id FROM main.index_csp)
                            """).fetchall()
    if mode == "index_ta":
        res1 = conn.execute("""SELECT * FROM main.index_ta
                               WHERE keywords_id NOT IN
                             (SELECT keywords_id FROM db2.index_ta)
                            """).fetchall()
        res2 = conn.execute("""SELECT * FROM db2.index_ta
                               WHERE keywords_id NOT IN
                             (SELECT keywords_id FROM main.index_ta)
                            """).fetchall()
    res1_set = set(res1)
    res2_set = set(res2)
    result: set = res1_set.symmetric_difference(res2_set)

    return result


def update_addr_index_csp(index_csp_path: Union[str, Path],
                          new_addr: str,
                          row_id: int) -> None:
    """
    Update the csp_keywords_address to new_addr at the row defined by row_id.

    :param index_csp_path:
    :param new_addr: the new address to be updated
    :param row_id: the row id where
    :return:
    """
    conn: Connection = create_connection(index_csp_path)
    cur: Cursor = conn.cursor()
    sql = ''' UPDATE index_csp
              SET csp_keywords_address = ?
              WHERE csp_keywords_id = ?'''
    cur.execute(sql, (new_addr, row_id))
    conn.commit()


def increase_num_search_index_ta(index_ta_path: Union[str, Path],
                                 new_num_searches: int,
                                 row_id: int) -> None:
    """

    :param index_ta_path:
    :param new_num_searches: the new address to be updated
    :param row_id: the row id where
    :return:
    """
    conn: Connection = create_connection(index_ta_path)
    cur: Cursor = conn.cursor()
    sql = ''' UPDATE index_ta
              SET keyword_numsearch = ?
              WHERE keywords_id = ?'''
    cur.execute(sql, (new_num_searches, row_id))
    conn.commit()


def get_all_table_paths(project_path: str) -> List[Path]:
    database_str_paths: List[str] = ['data_owner/indexes/index_ta.db',
                                     'trusted_authority/index_ta.db',
                                     'cloud_service_provider/index_csp.db']
    return [Path(project_path)/path for path in database_str_paths]


def show_tables(project_path: str,
                mode: str = "all"):
    """
    Get all the tables in the project and fetch them out.

    :return:
    """
    log.info(f"------------------------- Show all the tables -------------------------")
    database_paths: List[Path] = get_all_table_paths(project_path)
    for path in database_paths:
        if 'csp' in path.name:
            fetch_index_csp(index_csp_path=path,
                            actor="main",
                            mode=mode)
        elif 'ta' in path.name:
            fetch_index_ta(index_ta_path=path,
                           actor="main",
                           mode=mode)
        else:
            pass


def decrease_index_ta_num_files(index_ta_path: Union[str, Path],
                                rows: List[Tuple[str, int]]) -> None:
    """
    Update the num_files of a keyword in the table given by index_ta_path
    at the row defined by row_id.

    :param index_ta_path:
    :param rows: the rows where the number of files will be decreased.
    :return:
    """
    conn: Connection = create_connection(index_ta_path)
    cur: Cursor = conn.cursor()
    for hashed_word, num_files_w in rows:
        sql = ''' UPDATE index_ta
                  SET keyword_numfiles = ?
                  WHERE keyword = ? AND keyword_numfiles = ?'''
        cur.execute(sql, (num_files_w - 1, hashed_word, num_files_w))
        conn.commit()


def delete_rows_index_ta(index_ta_path: Path,
                         delete_rows: List[Tuple[str, int]]) -> None:
    """
    Delete rows in index_ta table by the hashed word and num files of that word.

    :param index_ta_path: the path to the index_ta.db.
    :param delete_rows: the list of tuples of hashed word and their num of files
                        which will be deleted.
    :return:
    """
    conn: Connection = create_connection(index_ta_path)
    cur = conn.cursor()
    for hashed_word, num_files_w in delete_rows:
        sql = 'DELETE FROM index_ta ' \
              'WHERE keyword=? AND keyword_numfiles=?'
        cur.execute(sql, (hashed_word, num_files_w))
        conn.commit()


def delete_rows_index_csp(index_csp_path: Path,
                          delete_rows: List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]]) \
        -> None:
    """
    Delete the rows in index_csp table by the hashed word and num files of that word.

    :param index_csp_path:
    :param delete_rows:
    :return:
    """
    conn: Connection = create_connection(index_csp_path)
    cur = conn.cursor()
    for addresses_w, values_w in delete_rows:
        sql = 'DELETE FROM index_csp ' \
              'WHERE csp_keywords_address=? AND csp_keywords_value=?'
        cur.execute(sql, (addresses_w[0], values_w[0]))
        conn.commit()


def change_addr_val_w_index_csp(index_csp_path: Path,
                                rows: List[Tuple[Tuple[str, str], Tuple[bytes, bytes]]]) \
        -> None:
    """
    Change the values of the row in the index_csp table where the old and new
    values are stored in the parameter 'rows'.

    :param index_csp_path:
    :param rows:
    :return:
    """
    conn: Connection = create_connection(index_csp_path)
    cur = conn.cursor()
    for addresses_w, values_w in rows:
        sql = ''' UPDATE index_csp
                  SET csp_keywords_address = ?, csp_keywords_value = ?
                  WHERE csp_keywords_address = ? AND csp_keywords_value = ?'''
        cur.execute(sql, (addresses_w[1], values_w[1], addresses_w[0], values_w[0]))
        conn.commit()
