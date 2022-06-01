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

##########################
#####   FUNCTIONS    #####
##########################
    
def _input_pasw():
    """ input password to encrypt content files

    Returns:
        hex: hash password
    """
    tmp_pasw = getpass(prompt='password: ')
    pasw_to_sha = sha1(tmp_pasw.encode('utf-8'))
    pasw = bytes(pasw_to_sha.hexdigest(), encoding='utf8')
    
    return pasw


def _input_salt():
    """ input 'salt' to encrypt content files

    Returns:
        hex: hash 'salt'
    """
    tmp_salt = getpass(prompt='salt: ')
    salt_to_sha = sha1(tmp_salt.encode('utf-8'))
    salt = bytes(salt_to_sha.hexdigest(), encoding='utf8')

    return salt


def _make_key():
    """ make key with SALT & PASW

    Returns:
        fernet_hex: key to encrypt
    """    
    logging.warning('### make key ###')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT, 
        iterations=390000
    )
    klucz = base64.urlsafe_b64encode(kdf.derive(PASW))    
    logging.warning(f'# key => {klucz}')

    return Fernet(klucz)


def _return_file_name_from_path(path_or_title):
    """ secretes name file //wydziela

    Args:
        path_or_name (str): path to file

    Returns:
        str: _description_
    """    
    list_elements = path_or_title.split('/')
    if len(list_elements) == 1:
        name_file = list_elements[0]
    else:
        name_file = list_elements[len(list_elements) -1]
        
    return name_file


def return_file_title(title_file):
    """_summary_

    Args:
        title_file (_type_): _description_

    Returns:
        _type_: _description_
    """    
    org_title = title_file.split('.')
    only_title = org_title[0]

    return only_title


def return_file_sufix(title_file):
    """returned sufix file

    Args:
        title_file (): title file

    Returns:
        _type_: 
    """    
    org_title = title_file.split('.')
    only_sufix = org_title[1]

    return only_sufix


def _fun_to_encrypt_file(file, path_file, dest_path):
    # czyta oryginalny plik 
    with open(f'{path_file}', 'r') as mysec:                
        oryginal = mysec.read()
    
    # zmaina nazwy pliku na old_name.sc
    file_sc = return_file_title(file) + '.sc'
    
    # zachowanie oryginalnego rozszezenia...
    sufix_to_sc = '.' + return_file_sufix(file) + '\n'

    # ... i szyfrowanie
    oryginal = sufix_to_sc + oryginal
    enc_mysec = FERN.encrypt(oryginal.encode('utf8'))
    
    # zapis do pliku.
    with open(f'{dest_path}{file_sc}', 'wb') as encrypted_file:
        encrypted_file.write(enc_mysec)


def _fun_to_decrypt_file(path_file):
    with open(path_file, 'rb') as my_sec:
        to_decrypt = my_sec.read()
        decrypt = FERN.decrypt(to_decrypt)

            # 2 save decrypt content to *sc
        with open(path_file, 'wb') as file_decrypt:                    
            file_decrypt.write(decrypt)

            # 3 read first line and other from *.sc
        with open(path_file, 'rb') as file_to_chenge_sufix:
            sufix_org = file_to_chenge_sufix.readline().decode('utf8').rstrip()
            rest = file_to_chenge_sufix.read()
                
            # 4 remove file *.sc
        remove(path_file)

            # 5 chenge sufix *.oryginal_sufix        
        new_path_to_file_decrypt = path_file[:-3] + sufix_org
        logging.warning(f' sciezka do odszyfrowanego pliku: {new_path_to_file_decrypt}')
                
            # 6 open *.oryginal_sufix and write decrypt content
        with open(new_path_to_file_decrypt, 'bw') as new_file:
            new_file.write(rest)


def _encrypt(PATH):
    """ encrypt files contents  
    """
    logging.warning('* * * start encrypt * * *')
    
    # encrypt one file
    if isfile(PATH):
        file_name_to_sc = _return_file_name_from_path(PATH)
        makedirs (f'{DEST}', exist_ok=True)
        dest_path = DEST + '/'
        _fun_to_encrypt_file(file_name_to_sc, PATH, dest_path)
        
    else:        
    # encrypt files in many directors
        # sprawdza czy PATH wprowadzony ma / na koncu
        if PATH[-1:] !=  '/':
            PATH = PATH + '/'
        for path, _ , files in walk(PATH):

            # sprawdza czy ostatni znak path to '/'            
            if path[-1:] != '/':
                path = path + '/'

            # 'odcina' czesc sciezki, ktora zawiera sciezke bezwzgledna
            if path == PATH:
                new_path = ''
            else:
                new_path = path[ -(len(path) - len(PATH) +1):]

                # sprawdza czy pierwszy wyraz sciezki to '/' i odcina 
                if new_path[0] == '/':
                    new_path = new_path[1:]
            
            dest_path = DEST + '/' + new_path
            makedirs (f'{dest_path}', exist_ok=True)

            for file in files:
                fun_path = path + file
                _fun_to_encrypt_file(file, fun_path, dest_path)


def _decrypt():
    logging.warning('* * * start decrypt * * *')
    if isfile(PATH):
        _fun_to_decrypt_file(PATH)        
    else:
        # decrypt many files
        for path, _ , files in walk(PATH):
            # check first char in path
            if path[-1:] != '/':
                path = path + '/'

            for file in files:
                path_file = path + file

                _fun_to_decrypt_file(path_file)


def _add():
    logging.warning('* * * start add * * *')
    if isfile(PATH):
        atext = input('wprowadz dane: ')
        add_text = '\n' + atext
        add_text = add_text.encode('utf-8')

        # odszyfrowac
        with open(PATH, 'rb') as my_sec:
            to_decrypt = my_sec.read()
                    
        decrypt = FERN.decrypt(to_decrypt)
        
        # zapisywanie odszyfrowanego tekstu
        with open(PATH, 'wb') as file_decrypt:
            file_decrypt.write(decrypt)            
            file_decrypt.write(add_text)

        # szyfrowanie całości
        with open(PATH, 'rb') as add_file:
            to_encrypt = add_file.read()        
        new_encrypt = FERN.encrypt(to_encrypt)
        
        # zapisywanie zaszyfrowanej całości
        with open(PATH, 'bw') as file_encrypt:
            file_encrypt.write(new_encrypt)
        

##########################
#####      MAIN      #####
##########################

if __name__ == '__main__':

####   input choice   ####

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-p', '--path',
        help='pasw - password to encrypt/decrypt'
    )

    parser.add_argument(
        '-d', '--destination',
        default='./backup',
        help='path to encrypt data - default is ./backup'
    )

    parser.add_argument(
        '-m', '--mode',
        choices=['encrypt', 'decrypt', 'add'],
        help='choice mode encrypt/decrypt files'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='three level verbose choises: 0 - default or -v, -vv'
    )

    args = parser.parse_args()

    PATH = args.path
    DEST = args.destination
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