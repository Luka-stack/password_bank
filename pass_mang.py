from cryptography.fernet import Fernet
import PySimpleGUI as sg
import pyperclip
import sqlite3
import random
import string
import os

sg.theme('DarkBrown1')

# TMP
CURRENT_FOLDER = '.'
USERS_DB = os.path.join(CURRENT_FOLDER, '.users.db')

CUR_LOGIN = ''
CUR_KEY   = ''

text_font = {'justification': 'left', 'font': ('Georgia', 12, 'bold'), 'pad': (1, 5)}
popup_font = {'font': ('Havletica', 12)}
btn_font  = {'font': ('Lato', 12, 'italic'), 'pad': (5, 7)}

def loginWindow():
    layout = [
        [sg.T('Login', size=(10, 1), **text_font), sg.In(size=(15, 1), **text_font)],
        [sg.T('Password', size=(10,1), **text_font), sg.In(password_char='*', size=(15, 1), **text_font)],
        [sg.T(' ' * 7), sg.Button('Sign Up', **btn_font), sg.T(' ' * 6), sg.Button('Log In', **btn_font)],
        [sg.T(' ' * 2), sg.Button('Exit', size=(23, 1), **btn_font)]
    ]

    window = sg.Window('Login', layout, finalize=True)

    while True:
        event, values = window.Read()

        if event is None or event == 'Exit':
            window.close()
            return False
        if event == 'Sign Up':
            if len(values[0]) > 0 and len(values[1]) > 0:
                signUp(values[0].lower(), values[1])
            else:
                sg.popup_ok('Login and password cannot be empty', title='Register', **popup_font)
        if event == 'Log In':
            if len(values[0]) > 0 and len(values[1]) > 0:
                if logIn(values[0].lower(), values[1]):
                    window.close()
                    return True
            else:
                sg.popup_ok('Login and password cannot be empty', title='Register', **popup_font)


def signUp(login, passwd):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    
    try:
        cursor.execute('CREATE TABLE users \
                        (login TEXT PRIMARY KEY NOT NULL, passwd TEXT NOT NULL, secret TEXT NOT NULL)')
    except:
        
        cursor.execute('SELECT * FROM users WHERE login=?', (login,))

        if cursor.fetchone():
            sg.popup_ok(f'User \'{login}\' already exists', title='Register', **popup_font)
            conn.close()
            return
    
    key = Fernet.generate_key()
    fernet = Fernet(key)
    enc_passwd = fernet.encrypt(passwd.encode())

    cursor.execute('INSERT INTO users VALUES(?,?,?)', (login, enc_passwd, key))
    conn.commit()
    conn.close()
            
    sg.popup_ok(f'User \'{login}\' has successfully oppend password bank', title='Register', **popup_font)


def logIn(login, passwd):
    global CUR_LOGIN, CUR_KEY

    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE login=?', (login,))
    except:
        sg.popup_ok('Wrong Login or Password', title='Login Error', **popup_font)
        return False

    row = cursor.fetchone()
    if row:

        fernet = Fernet(row[2])
        dec_passwd = fernet.decrypt(row[1]).decode()

        if passwd == dec_passwd:
            sg.popup_no_buttons("Logging...", auto_close=True, auto_close_duration=3, **popup_font)

            CUR_LOGIN = login
            CUR_KEY   = row[2]

            return True

    sg.popup_ok('Wrong Login or Password', title='Login Error', **popup_font)
    return False


def mainWindow():
    global accounts
    
    # Get All accounts and store them all
    accounts = getAccounts()

    window = drawMainWindow()

    while True:
        event, values = window.Read()
        redraw = False

        if event is None or event == 'Exit':
            break

        if event.startswith('sh'):
            popupShowAccount(event.split('_')[1])

        if event == 'bank_passwd':
            popupChangeBankPassword()

        if event.startswith('dl'):
            redraw = popupDeleteAccount(event.split('_')[1])
        
        elif event.startswith('ch'):
            acc = event.split('_')[1]
            redraw = popupAddOrUpdate(acc, accounts[acc][0], accounts[acc][1])

        elif event == 'add_acc':
            redraw = popupAddOrUpdate()

        if redraw:
            accounts = getAccounts()
            args = {'location': window.CurrentLocation(), 'alpha_channel': 0}

            newWindow = drawMainWindow(args)
            newWindow.SetAlpha(1)
            window.Close()
            window = newWindow

    window.close()


def drawMainWindow(args={}):

    # create left, right column and put them into layout
    left_column, right_column = createLeftColumn(accounts), createRightColumn()
    layout = createLayout(left_column, right_column)

    return sg.Window('Password Bank', layout, finalize=True, **args)


# Create Layout For The Left Column
def createLeftColumn(data):
    left_column = [
        [sg.Text('Accounts', size=(20, 1), justification='center', font=('KacstTitle', 15, 'italic'), text_color='gold')],
        [sg.VerticalSeparator((133, 3))],
    ]

    for k in data.keys():
        acc_row = [sg.Frame(title=k.capitalize(), relief=sg.RELIEF_SOLID, font=('italic'),
                            layout=[[sg.Button('Show',   key='sh_' + k, size=(5, 1), **btn_font),
                                     sg.Button('Change', key='ch_' + k, size=(5, 1), **btn_font),
                                     sg.Button('Delete', key='dl_' + k, size=(5, 1), **btn_font)]]
                            )
                ]
        left_column.append(acc_row)

    return left_column


# Create Layout For The Right Column
def createRightColumn():
    right_column = [
        [sg.T(' '), sg.Text(f'- {CUR_LOGIN.capitalize()} -', size=(17, 1), text_color='yellow', justification='center', 
                font=('Comic Sans MS', 15), relief=sg.RELIEF_SUNKEN)],
        [sg.VerticalSeparator((125, 5))],
        [sg.T(' ' * 8),  sg.Button('Add New Account', key='add_acc', **btn_font)],
        [sg.VerticalSeparator((125, 5))],
        [sg.T(' ' * 3),  sg.Button('Change Password Bank', key='bank_passwd', **btn_font)],
        [sg.VerticalSeparator((125, 5))],
        [sg.T(' ' * 18), sg.Button('Exit', size=(6, 1))]
    ]

    return right_column


# Create Layout For The Entire Window
def createLayout(left_column, right_column):
    layout = [
        [sg.Col(left_column,size=(300, 200), scrollable=True, vertical_scroll_only=True), 
         sg.Col(right_column)]
    ]

    return layout


def popupAddOrUpdate(acc='', login='', passwd=''):

    if passwd:
        passwd = Fernet(CUR_KEY).decrypt(passwd).decode()

    popup = sg.Window('Add' if not acc else acc, finalize=True, layout=
        [[sg.Text('Account',  size=(8, 1), **text_font), sg.Input(size=(20, 1), default_text=acc,   **text_font)],
         [sg.Text('Login',    size=(8, 1), **text_font), sg.Input(size=(20, 1), default_text=login, **text_font)],
         [sg.Text('Password', size=(8, 1), **text_font),
          sg.Input(size=(20, 1), default_text=passwd, password_char='*', key='pw', **text_font),
          sg.Input(size=(20, 1), default_text=passwd, key='pw_vis', visible=False, **text_font)],
         [sg.T(' ' * 35), sg.Button('Generate Password', key='gen', **btn_font)],
         [sg.T(' ' * 2), sg.Button('Save', size=(8, 1), **btn_font), sg.T(' ' * 8), sg.Cancel(size=(10, 1), **btn_font)]
    ])

    popup['pw'].bind('<Enter>', '-ent')
    popup['pw_vis'].bind('<Leave>', '-lve')
    
    while True:
        event, values = popup.Read()

        if event is None or event == 'Cancel':
            break

        if event == 'gen':
            generated = generatePassword()
            popup['pw'].update(generated)
            popup['pw_vis'].update(generated)
        
        if event == 'pw-ent':
            popup['pw'].update(visible=False)
            popup['pw_vis'].update(visible=True)
            popup['pw_vis'].set_focus(True)
            popup['pw_vis'].update(values['pw'])

        if event == 'pw_vis-lve':
            popup['pw_vis'].update(visible=False)
            popup['pw'].update(visible=True)
            popup['pw'].set_focus(True)
            popup['pw'].update(values['pw_vis'])

        if event == 'Save':
            if addOrUpdateAccount(values[0].lower(), values[1].lower(), values['pw']):
                popup.close()
                return True

    popup.close()
    return False


def popupChangeBankPassword():

    popup = sg.Window('Change Password Bank', finalize=True, layout=
        [[sg.Text('Old Password',  size=(12, 1), **text_font), sg.Input(size=(20, 1), password_char='*', focus=True, **text_font)],
         [sg.Text('New Password',  size=(12, 1), **text_font),
          sg.Input(size=(20, 1), password_char='*', key='pw', **text_font),
          sg.Input(size=(20, 1), visible=False,     key='pw_vis', **text_font)],
         [sg.T(' ' * 46), sg.Button('Generate Password', key='gen', **btn_font)],
         [sg.T(' ' * 5),  sg.Button('Save', size=(10, 1), **btn_font), sg.T(' ' * 12), sg.Cancel(size=(10, 1), **btn_font)]
    ])

    popup['pw'].bind('<Enter>', '-ent')
    popup['pw_vis'].bind('<Leave>', '-lve')

    while True:
        event, values = popup.Read()

        if event is None or event == 'Cancel':
            break

        if event == 'gen':
            generated = generatePassword()
            popup['pw'].update(generated)
            popup['pw_vis'].update(generated)

        if event == 'pw-ent':
            popup['pw'].update(visible=False)
            popup['pw_vis'].update(visible=True)
            popup['pw_vis'].set_focus(True)
            popup['pw_vis'].update(values['pw'])

        if event == 'pw_vis-lve':
            popup['pw_vis'].update(visible=False)
            popup['pw'].update(visible=True)
            popup['pw'].set_focus(True)
            popup['pw'].update(values['pw_vis'])

        if event == 'Save':
            if saveBankPassword(values[0], values['pw']):
                break

    popup.close()


def generatePassword():
    # strong password length
    MAX_LEN = 12

    # character pool
    pool = string.ascii_lowercase + string.ascii_uppercase + \
        string.digits + string.punctuation

    # randomly select at least one character from every set
    rand_digit = random.choice(string.digits)
    rand_lower = random.choice(string.ascii_lowercase)
    rand_upper = random.choice(string.ascii_uppercase)
    rand_smbl  = random.choice(string.punctuation)

    password = rand_digit + rand_lower + rand_upper + rand_smbl
    password = list(password)

    for _ in range(MAX_LEN - 4):
        password.append(random.choice(pool))
        random.shuffle(password)

    return ''.join(password)


def getAccounts():
    user_bank = os.path.join(CURRENT_FOLDER, '.' + CUR_LOGIN + '.db')
    conn = sqlite3.connect(user_bank)
    cursor = conn.cursor()

    try:
        cursor.execute('CREATE TABLE accounts \
                       (acc TEXT PRIMARY KEY NOT NULL, login TEXT NOT NULL, passwd TEXT NOT NULL)')
    except:
        pass

    cursor.execute('SELECT * FROM accounts')
    rows = cursor.fetchall()

    rows_by_acc = {}
    for row in rows:
        rows_by_acc[row[0]] = [row[1], row[2]]

    return rows_by_acc


def popupShowAccount(acc):

    passwd = Fernet(CUR_KEY).decrypt(accounts[acc][1]).decode()

    popup = sg.Window(acc, finalize=True, layout=
        [[sg.Text('Login',    size=(8, 1), **text_font), sg.Text(accounts[acc][0], text_color='burlywood1', font=('Georgia', 13), pad=(1, 5))],
         [sg.Text('Password', size=(8, 1), **text_font),
          sg.Text('******', text_color='burlywood1', font=('Georgia', 13), pad=(1, 5), key='pw'),
          sg.Text(passwd, text_color='burlywood1', font=('Georgia', 13), pad=(1, 5), key='pw_vis', visible=False)],
         [sg.T(' ' * 16), sg.Button('Copy Password', key='c_pw', **btn_font)],
         [sg.OK(size=(20, 1), **btn_font)]
    ])

    popup.bind('<Motion>', 'ent')
    popup['pw'].bind('<Enter>', 'ent')

    while True:
        event, values = popup.Read()

        if event is None or event == 'OK':
            break

        if event == 'pwent':
            popup['pw'].update(visible=False)
            popup['pw_vis'].update(visible=True)

        if event == 'ent':
            popup['pw_vis'].update(visible=False)
            popup['pw'].update(visible=True)

        if event == 'c_pw':
            pyperclip.copy(passwd)

    popup.close()


def popupDeleteAccount(acc):
    
    answer = sg.popup_yes_no('Do you want to delete', f'{acc} account?',
                             title='Delete ' + acc, **popup_font)

    if answer == 'Yes':
        query = 'DELETE FROM accounts WHERE acc=?'
        executeQuerryAccount(query, (acc,))
        return True
    
    return False


def addOrUpdateAccount(acc, login, passwd):
    
    # check site
    # check login
    # check passwd
    if len(acc) > 0 and len(login) > 0 and len(passwd) > 0:
        if accounts.get(acc, ''):
            answer = sg.popup_yes_no(f'Accaount {acc} already exists.', 'Do you want to replace it?',
                                     title='Replace ' + acc, **popup_font)
            
            if answer == 'Yes':
                query = 'UPDATE accounts SET login=?, passwd=? WHERE acc=?'
                values = (login, Fernet(CUR_KEY).encrypt(passwd.encode()), acc)
            else:
                return False

        else:
            query = 'INSERT INTO accounts VALUES (?, ?, ?)'
            values = (acc, login, Fernet(CUR_KEY).encrypt(passwd.encode()))

    else:
        sg.popup_ok('Account, Login and password cannot be empty', title='Creat Account', **popup_font)
        return False

    executeQuerryAccount(query, values)
    return True


def executeQuerryAccount(query, values):
    user_bank = os.path.join(CURRENT_FOLDER, '.' + CUR_LOGIN + '.db')
    conn = sqlite3.connect(user_bank)
    cursor = conn.cursor()

    try :
        cursor.execute('CREATE TABLE accounts \
                       (acc TEXT PRIMARY KEY NOT NULL, login TEXT NOT NULL, passwd TEXT NOT NULL)')
    except:
        pass

    cursor.execute(query, values)
    conn.commit()    
    conn.close()


def saveBankPassword(old_passwd, new_passwd):

    if len(old_passwd) > 0 and len(new_passwd) > 0:

        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE login=?', (CUR_LOGIN, ))

        row = cursor.fetchone()
        fernet = Fernet(CUR_KEY)
        
        if old_passwd == fernet.decrypt(row[1]).decode():
            cursor.execute('UPDATE users SET passwd=? WHERE login=?', (fernet.encrypt(new_passwd.encode()), CUR_LOGIN))

            sg.popup_ok('You successfully changed your password bank', title='Change Password', **popup_font)

            conn.commit()
            cursor.close()
            return True

        else:
            sg.popup_ok('Wrong Old Password', title='Change Password', **popup_font)
            cursor.close()
            return False

    else:
        sg.popup_ok('Old and New password cannot be empty', title='Change Password', **popup_font)
        return False


def main():
    logged = loginWindow()
    
    if logged:
        mainWindow()
    

if __name__ == '__main__':
    main()
