from Cryptodome.Cipher import AES 
from Cryptodome.Util.Padding import pad 
from Cryptodome.Util.Padding import unpad
import hashlib
import os
import json
import zipfile

device_id = ''
username = ''
RidibooksPath = os.getenv('APPDATA') + '\\Ridibooks'
outDir = ''

def printLog(level, msg):
    match(level):
        case -1:
            print("[ERROR] " + msg + "\n")
        case 0: 
            print('\n|--> ' + msg, end = "")
        case 1: 
            print('\n  |---> ' + msg, end = "")
        case 2: 
            print('\n    |-----> ' + msg, end = "")
        case 100:
            print("    ..." + msg, end = "")            

def getBookJson(bookPath):
    try:
        with open(bookPath, "rb") as f:
            ciphertext = f.read()
        key = hashlib.sha1(f'book-{username}'.encode()).hexdigest()[2:18]
        aes = AES.new(key.encode(), AES.MODE_ECB)
        plaintext = aes.decrypt(ciphertext[256:])
        result = unpad(plaintext, 16)
        return json.loads(result)
    except FileNotFoundError:
        printLog(-1, 'Possibly incorrect username. Please double check!')
        return -1

def getkey(deviceId, datFile, format): 
    offset = 68
    zipoffset = 2
    try:  
        with open(datFile, "rb") as f:
            iv = f.read(16)
            ciphertext = f.read()
    except FileNotFoundError:
        return -1
    aes = AES.new(deviceId.encode(), AES.MODE_CBC, bytes(iv))
    result = aes.decrypt(pad(ciphertext, 16))
    return result[offset:offset + 16] if format != 'zip' else result[zipoffset:zipoffset + 16]

def decryptBook(key, encryptedBookFile, outFile):
    try:  
        with open(encryptedBookFile, "rb") as infile:
            iv = infile.read(16)
            ciphertext = infile.read()
    except FileNotFoundError:
        return -1

    with open(outFile, "wb") as outfile:
        aes = AES.new(key, AES.MODE_CBC, bytes(iv))
        plaintext = aes.decrypt(pad(ciphertext, 16))
        outfile.write(plaintext)
    return 0

def buildPath(id, filename, ext):
    libraryPath = f'{RidibooksPath}\\library'
    return f'{libraryPath}\\{username}\\{id}\\{filename}.{ext}' if ext != '' else f'{libraryPath}\\{username}\\{id}\\{filename}'

def createDir(name):
    current = os.getcwd()
    dir = os.path.join(current, name)
    if not os.path.exists(dir):
        os.makedirs(dir)
    return dir

def validateFile(title):
    invalidFileChars = '<>:"/\|?*'
    for char in invalidFileChars:
        title = title.replace(char, '')
    return title

def run(summaryDict):
    bookPath = f'{RidibooksPath}\\datastores\\user\\{username}\\book'
    jsondict = getBookJson(bookPath)

    for value in jsondict['downloaded'].values():
        id = value['id']
        title = value['title']['main']
        format = value['format']
        if (format == 'bom'):
            format = 'zip'

        filename = validateFile(title)
        datfile = buildPath(id, id, 'dat')
        encfile = buildPath(id, id, format)
        key = getkey(device_id[0:16], datfile, format)

        printLog(0, f'Decrypting [{title}]')

        if key == -1:
            summaryDict['fail'].append(title) 
            printLog(1, f'[{id}.dat] not found. Book library may be out of date. Skipping this entry')
            continue
        
        if (format == 'zip'): #comic books
            failFlag = False
            unzipPath = buildPath(id, id, '')
            printLog(1, f'Unzipping [{encfile}]')
            with zipfile.ZipFile(encfile,"r") as zip_ref:
                zip_ref.extractall(unzipPath)
                printLog(100, 'OK')
            
            for file in os.scandir(unzipPath):
                if file.name == 'zzzzzzzzzz':
                    os.remove(file.path)
                    continue
                if file.is_file():
                    newDir = createDir(f'DRM-REMOVED\\{title}')
                    decfile = newDir + "\\" + file.name
                    printLog(2, f'Decrypting [{file.name}]')
                    if (decryptBook(key, file.path, decfile) == -1):
                        failFlag = True
                        printLog(100, 'FAIL')
                    else:
                        printLog(100, 'OK')

                    os.remove(file.path)
            os.rmdir(unzipPath)
            if (failFlag):
                summaryDict['fail'].append(title) 
            else:
                summaryDict['success'].append(title) 

        else: # epub or pdf
            if(decryptBook(key, encfile, f'{outDir}\\{filename}.{format}') == -1):
                summaryDict['fail'].append(title) 
                printLog(1, f'[{encfile}] not found.')
                printLog(1, f'Delete and re-download [{title}] from the ridibooks viewer program and DO NOT to open it from the viewer')    
            else:
                summaryDict['success'].append(title)
                printLog(100, 'OK')

def displaySummary(summaryDict):
    successCount = len(summaryDict['success'])
    failCount = len(summaryDict['fail'])

    print('\n\n------------------------------------------[SUMMARY]------------------------------------------')
    printLog(0, f'SUCCESS total: {successCount}') 
    for title in summaryDict['success']:
        printLog(1, title) 
    printLog(0, f'FAIL total: {failCount}')   
    for title in summaryDict['fail']:
        printLog(1, title) 

#########################################################

username = str(input('Enter Ridibooks username: '))
device_id = str(input('Enter PC device id (Log in via https://ridibooks.com/account/login and go to https://account.ridibooks.com/api/user-devices/app and find "device_id"): '))

if(len(device_id) == 36):
    outDir = createDir('DRM-REMOVED')
    summaryDict = {'success': [], 'fail': []}
    run(summaryDict)
    displaySummary(summaryDict)
    printLog(0, f'Decrypted files located in [{outDir}]')
else:
    printLog(-1,'invalid device id! Correct format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')

input("\n\n...press any key to exit") 