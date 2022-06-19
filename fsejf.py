import argparse
import logging
from os import walk, makedirs, remove
from os.path import isfile
from getpass import getpass
import base64
from hashlib import sha1
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import pathlib
import shutil

##########################
#####   FUNCTIONS    #####
##########################
    
def _input_pasw():
    tmp_pasw = getpass(prompt='password: ')
    pasw_to_sha = sha1(tmp_pasw.encode('utf-8'))
    pasw = bytes(pasw_to_sha.hexdigest(), encoding='utf8')
    
    return pasw


def _input_salt():
    tmp_salt = getpass(prompt='salt: ')
    salt_to_sha = sha1(tmp_salt.encode('utf-8'))
    salt = bytes(salt_to_sha.hexdigest(), encoding='utf8')

    return salt


def _make_key():
    if args.verbose:
        logging.warning('* * * make key * * * ')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT, 
        iterations=390000
    )
    klucz = base64.urlsafe_b64encode(kdf.derive(PASW))    
    if args.verbose:
        logging.warning(f'# key => {klucz}')

    return Fernet(klucz)


def _fun_decrypt(path_file):
    with open(path_file, 'rb') as my_sec:
        to_decrypt = my_sec.read()
        decrypt = FERN.decrypt(to_decrypt)

    # save decrypt content to *sc
    with open(path_file, 'wb') as file_decrypt:                    
        file_decrypt.write(decrypt)

    # read first line and other from *.sc
    with open(path_file, 'rb') as file_to_chenge_sufix:
        suffix_org = file_to_chenge_sufix.readline().decode('utf8').rstrip()
        rest = file_to_chenge_sufix.read()
            
    with open(path_file, 'bw') as new_file:
        new_file.write(rest)
    
    path_file.rename(path_file.with_suffix(suffix_org))


def _fun_encrypt(path_z_innej_funkcji):
    path = path_z_innej_funkcji
    with open(path, 'br') as plik_do_szyfrowania:
        tresc_z_pliku = plik_do_szyfrowania.read()
    
    tresc_do_szyfrowania = path.suffix + '\n' + tresc_z_pliku.decode('utf-8')

    zaszyfrowana_tresc = FERN.encrypt(tresc_do_szyfrowania.encode('utf-8'))
    
    with open(path, 'wb') as plik_do_szyfrowania:
        plik_do_szyfrowania.write(zaszyfrowana_tresc)

    pathlib.Path(path).rename(path.with_suffix('.sc'))


def _encrypt(PATH):
    if args.verbose:
        logging.warning('* * * start encrypt * * *')

    if PATH.is_file():
        _fun_encrypt(PATH)
    else:
        for path, _ , files in walk(PATH):
            path = pathlib.Path(path)
            for file in files:             
                file = pathlib.Path(file)
                path_to_file = path.joinpath(file)
                _fun_encrypt(path_to_file)


def _decrypt():
    if args.verbose:
        logging.warning('* * * start decrypt * * *')

    if isfile(PATH):
        _fun_decrypt(PATH)        
    else:
        for path, _ , files in walk(PATH):
            path = pathlib.Path(path)
            for file in files:
                file = pathlib.Path(file)
                path_file = path.joinpath(file)
                _fun_decrypt(path_file)


def _add():
    if args.verbose:
        logging.warning('* * * start add * * *')
    
    if isfile(PATH):
        atext = input('wprowadz dane: ')
        add_text = '\n' + atext
        add_text = add_text.encode('utf-8')

        with open(PATH, 'rb') as my_sec:
            to_decrypt = my_sec.read()
                    
        decrypt = FERN.decrypt(to_decrypt)
        
        with open(PATH, 'wb') as file_decrypt:
            file_decrypt.write(decrypt)            
            file_decrypt.write(add_text)

        with open(PATH, 'rb') as add_file:
            to_encrypt = add_file.read()        
        new_encrypt = FERN.encrypt(to_encrypt)
        
        with open(PATH, 'bw') as file_encrypt:
            file_encrypt.write(new_encrypt)


def _backup():
    if args.verbose:
        logging.warning('* * * start backup * * *')
    shutil.copytree(PATH, BKUP, dirs_exist_ok=True)
    _encrypt(BKUP)
        

##########################
#####      MAIN      #####
##########################

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-p', '--path',
        help='path to file to encrypt/decrypt'
    )
    
    parser.add_argument(
        '-b', '--backup',
        default=pathlib.Path().cwd().joinpath('backup'),
        help='path to encrypt backup data - default is ./backup'
    )

    parser.add_argument(
        '-m', '--mode',
        choices=['encrypt', 'decrypt', 'add', 'backup'],
        help='choice mode encrypt/decrypt files'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='one level verbose choises: 0 is default or -v'
    )

    args = parser.parse_args()

    PATH = pathlib.Path(args.path)
    BKUP = pathlib.Path(args.backup)
    MODE = args.mode
    PASW = _input_pasw()
    SALT = _input_salt()

    FERN = _make_key()
    
    if MODE == 'encrypt' and args.path:
        _encrypt(PATH)    

    if MODE == 'decrypt' and args.path:
        _decrypt()

    if MODE == 'add' and args.path:
        _add()

    if MODE == 'backup' and args.path:
        _backup()
