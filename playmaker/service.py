from gpapi.googleplay import GooglePlayAPI, LoginError, RequestError, SecurityCheckError
from subprocess import Popen, PIPE

import base64
import os
import sys
import concurrent.futures
import locale as locale_service
import json
import dict_digger
from datetime import datetime as dt
from pathlib import Path

NOT_LOGGED_IN_ERR = 'Not logged in'
WRONG_CREDENTIALS_ERR = 'Wrong credentials'
SESSION_EXPIRED_ERR = 'Session tokens expired, re-login needed'
FDROID_ERR = 'Error while executing fdroidserver tool'


def makeError(message):
    return {'status': 'ERROR',
            'message': message}

def get_app_detail(app, key):
    return dict_digger.dig(app, 'details', 'appDetails', key)

def get_details_from_apk(packageName, service):

    print('Fetching Details from Playstore for %s' % packageName)
    try:
        details = service.details(packageName)
    except RequestError as e:
        print('Cannot fetch Details from Playstore for %s' % packageName)
        return None
    return details


# TODO free all functions
class Play(object):
    def __init__(self, where, debug):
        self.currentSet = []
        self.totalNumOfApps = 0
        self.debug = debug
        self.firstRun = True
        self.loggedIn = False
        self._email = None
        self._passwd = None
        self._gsfId = None
        self._token = None
        self._last_fdroid_update = None

        self.fdroid             = where / 'fdroid'              # fdroid config/meta/...
        self.fdroid_repo        = where / 'fdroid' / 'repo'     # apks for fdroid
        self.playstore_download = where / 'playstore_download'  # apks from playstore

        if not self.fdroid.exists():
            self.fdroid.mkdir()

        if not self.playstore_download.exists():
            self.playstore_download.mkdir()

        # note that the 'repo' subfolder will be created in init of fdroid

        # configuring fdroid data
        if self.fdroid:
            self.fdroid_exe = 'fdroid'
            self.fdroid_init()

        # language settings
        locale = os.environ.get('LANG_LOCALE')
        if locale is None:
            locale = locale_service.getdefaultlocale()[0]
        timezone = os.environ.get('LANG_TIMEZONE')
        if timezone is None:
            timezone = 'Europe/Berlin'
        device = os.environ.get('DEVICE_CODE')
        if device is None:
            self.service = GooglePlayAPI(locale, timezone)
        else:
            self.service = GooglePlayAPI(locale, timezone, device_codename=device)

    def fdroid_init(self):
        found = False
        for path in os.environ['PATH'].split(':'):
            exe = os.path.join(path, self.fdroid_exe)
            if os.path.isfile(exe):
                found = True
                break
        if not found:
            print('Please install fdroid')
            sys.exit(1)
        #elif os.path.isfile('config.py'):
        fdroid_config = self.fdroid / 'config.py'
        if fdroid_config.exists():
            print('Repo already initalized, skipping init')
        else:
            p = Popen([self.fdroid_exe, 'init', '-v'], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate()
            if p.returncode != 0:
                sys.stderr.write("error initializing fdroid repository " +
                                 stderr.decode('utf-8'))
                sys.exit(1)
        # backup config.py
        if self.debug:
            print('Checking config.py file')
        with fdroid_config.open('r') as config_file:
            content = config_file.readlines()
        with fdroid_config.open('w') as config_file:
            # copy all the original content of config.py
            # if the file was not modified with custom values, do it
            modified = False
            for line in content:
                if '# playmaker' in line:
                    modified = True
                config_file.write(line)
            if not modified:
                if self.debug:
                    print('Appending playmaker data to config.py')
                config_file.write('\n# playmaker\nrepo_name = "playmaker"\n'
                                  'repo_description = "repository managed with '
                                  'playmaker https://github.com/NoMore201/playmaker"\n')

        # ensure all folder and files are setup
        p = Popen([self.fdroid_exe, 'update', '--create-key', '-v'], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            print('Skipping fdroid update')
        else:
            print('Fdroid repo initialized successfully')

    def get_last_fdroid_update(self):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}
        return {'status': 'SUCCESS',
                'message': str(self._last_fdroid_update)}

    def fdroid_update(self):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}
        if self.fdroid:
            try:
                p = Popen([self.fdroid_exe, 'update', '-c', '--clean'],
                          stdout=PIPE, stderr=PIPE)
                stdout, stderr = p.communicate()
                if p.returncode != 0:
                    sys.stderr.write("error updating fdroid repository " +
                                     stderr.decode('utf-8'))
                    return makeError(FDROID_ERR)
                else:
                    print('Fdroid repo updated successfully')
                    self._last_fdroid_update = dt.today().replace(microsecond=0)
                    return {'status': 'SUCCESS'}
            except Exception as e:
                return makeError(FDROID_ERR)
        else:
            return {'status': 'SUCCESS'}

    def get_apps(self):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}

        if self.firstRun:
            return {'status': 'PENDING',
                    'total': self.totalNumOfApps,
                    'current': len(self.currentSet)}
        return {'status': 'SUCCESS',
                'message': sorted(self.currentSet, key=lambda k: k['title'])}

    def set_encoded_credentials(self, email, password):
        self._email = base64.b64decode(email).decode('utf-8')
        self._passwd = base64.b64decode(password).decode('utf-8')

    def set_credentials(self, email, password):
        self._email = email
        self._passwd = password

    def set_token_credentials(self, gsfId, token):
        self._gsfId = int(gsfId, 16)
        self._token = token

    def has_credentials(self):
        passwd_credentials = self._email is not None and self._passwd is not None
        token_credentials = self._gsfId is not None and self._token is not None
        return passwd_credentials or token_credentials

    def login(self):
        if self.loggedIn:
            return {'status': 'SUCCESS', 'securityCheck': False, 'message': 'OK'}

        try:
            if not self.has_credentials():
                raise LoginError("missing credentials")
            self.service.login(self._email,
                               self._passwd,
                               self._gsfId,
                               self._token)
            self.loggedIn = True
            print('Logged in to Google Account')
            return {'status': 'SUCCESS', 'securityCheck': False, 'message': 'OK'}
        except LoginError as e:
            print('LoginError: {0}'.format(e))
            self.loggedIn = False
            return {'status': 'ERROR',
                    'securityCheck': False,
                    'message': 'Wrong credentials'}
        except SecurityCheckError as e:
            print('SecurityCheckError: {0}'.format(e))
            self.loggedIn = False
            return {'status': 'ERROR',
                    'securityCheck': True,
                    'message': 'Need security check'}
        except RequestError as e:
            # probably tokens are invalid, so it is better to
            # invalidate them
            print('RequestError: {0}'.format(e))
            self.loggedIn = False
            return {'status': 'ERROR',
                    'securityCheck': False,
                    'message': 'Request error, probably invalid token'}

    def update_state(self):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}

        print('Updating apks...')

        jsonFiles = list(self.playstore_download.glob('*.json'))
        for j in jsonFiles:
            with open(j) as f:
                obj = json.load(f)
                if 'title' in obj:
                    self.currentSet.append(obj)
            print("Found '{}'".format(obj['title']))

        print('(Would do an Update from Playstore now)')
        # TODO 'check_local_apks'
 
        if 0 == len(self.currentSet):
            print("No jsons found, will download them for all existing apks")
            apkFiles = list(self.playstore_download.glob('*.apk'))
            with concurrent.futures.ProcessPoolExecutor() as executor:
                future_to_app = [executor.submit(get_details_from_apk,
                                                apk.stem,
                                                self.service)
                                for apk in apkFiles]
                for future in concurrent.futures.as_completed(future_to_app):
                    app = future.result()
                    if app is not None and 'title' in app:
                        print("Got json for '{}'".format(app['title']))
                        self.currentSet.append(app)
                        packageName = get_app_detail(app, 'packageName')
                        filenameJson = packageName + '.json'
                        json.dump(app, open(self.playstore_download / filenameJson, "w"), indent=2)
                        # append version to apk filename
                        versionCode = get_app_detail(app, 'versionCode')
                        filenameApk = packageName + '.apk'
                        filenameApkVersion = packageName + '.apk.' + str(versionCode)
                        os.rename(self.playstore_download / filenameApk, self.playstore_download / filenameApkVersion)
                        print("Added Version Suffix '.{}' to apk of '{}'".format(versionCode, app['title']))


        apkVersions = []
        for apk in self.currentSet:
            apkName = get_app_detail(apk, 'packageName')
            apkVersions = list(self.playstore_download.glob(apkName+'.apk.*'))
            #print("apkVersions of '{}'= '{}'".format(apkName, apkVersions))

            # TODO consider info from somewhere which version to link to fdroid
            #      for now, its the most recent
            target = self.fdroid_repo / apkVersions[0].stem
            if target.exists() and target.is_symlink():
                target.unlink()
            os.symlink(apkVersions[0], target)
            print("Created Simlink to fdroid Repo for '{}'".format(apkVersions[0].name))

        self.firstRun = False


    def insert_app_into_state(self, newApp):

        newPackageName = get_app_detail(newApp, 'packageName')

        is_same_package = lambda app: get_app_detail(app, 'packageName') == newPackageName
        exist_index = next((index for (index, app) in enumerate(self.currentSet) if is_same_package(app)), None)

        #print("exist_index= {}".format(exist_index))

        if None != exist_index:
            print("{} is already cached, updating...".format(newPackageName))
            # XXX keep history of recent 1-2 versions
            self.currentSet[exist_index] = newApp
        else:
            print("Adding {} into cache...".format(newPackageName))
            self.currentSet.append(newApp)

        # TODO update json
        #json.dump(app, open(packageName+".json","w"), indent=0)


    def search(self, appName, numItems=15):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}

        try:
            apps = self.service.search(appName)
        except RequestError as e:
            print(e)
            self.loggedIn = False
            return {'status': 'ERROR',
                    'message': SESSION_EXPIRED_ERR}
        except LoginError as e:
            print(SESSION_EXPIRED_ERR)
            self.loggedIn = False
        except IndexError as e:
            print(SESSION_EXPIRED_ERR)
            self.loggedIn = False

        apps_nested = apps[0].get('child')[0].get('child')

        # TODO return info whats already existing
        return {'status': 'SUCCESS',
                'message': apps_nested}

    def details(self, app):
        try:
            details = self.service.details(app)
        except RequestError:
            details = None
        return details

    def get_bulk_details(self, apksList):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}
        try:
            apps = [self.details(a) for a in apksList]
        except LoginError as e:
            print(e)
            self.loggedIn = False
        return apps

    def download_selection(self, apps):

        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}

        # TODO merge with 'insert_app_into_state' and focus on version handling

        # success = []
        # failed = []
        # unavail = []

        # for app in apps:
        #     packageName = get_app_detail(app, 'packageName')
        #     print('Downloading %s from Playstore' % packageName) 
        #     data_gen = None
        #     versionCode = get_app_detail(app, 'versionCode')
        #     micros = app.get('offer')[0].get('micros')
        #     print("type(micros)= ".format(type(micros)))
        #     try:
        #         if micros == '0':
        #             data_gen = self.service.download(packageName, versionCode)
        #         else:
        #             data_gen = self.service.delivery(packageName, versionCode)
        #         data_gen = data_gen.get('file').get('data')
        #     except IndexError as exc:
        #         print(exc)
        #         print('Package %s does not exists in Playstore' % packageName)
        #         unavail.append(packageName)
        #         continue
        #     except Exception as exc:
        #         print(exc)
        #         print('Failed to download %s from Playstore' % packageName)
        #         failed.append(packageName)
        #         continue

        #     filenameApk = packageName + '.apk.' + str(versionCode)
        #     filenameJson = packageName + '.json'
  
        #     try:
        #         with open(self.playstore_download / filenameApk, 'wb') as apk_file:
        #             for chunk in data_gen:
        #                 apk_file.write(chunk)
        #         json.dump(app, open(self.playstore_download / filenameJson, "w"), indent=2)
        #     except IOError as exc:
        #         print('Error while writing %s: %s' % (filename, exc))
        #         failed.append(packageName)

        #     success.append(app)

        # for x in success:
        #     self.insert_app_into_state(x)

        # return {'status': 'SUCCESS',
        #         'message': {'success': success,
        #                     'failed': failed,
        #                     'unavail': unavail}}

    def check_local_apks(self):
        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}
        if len(self.currentSet) == 0:
            print('There is no package')
            return {'status': 'SUCCESS',
                    'message': []}
        toUpdate = []
        for app in self.currentSet:
            packageName = get_app_detail(app, 'packageName')
            try:
                # XXX why here no futures?!
                details = self.details(packageName)
                if details is None:
                    print('%s not available in Play Store' % packageName)
                    continue
                thisVersionCode = get_app_detail(app, 'versionCode')
                otherVersionCode = get_app_detail(details, 'versionCode')
                if self.debug:
                    print('Checking %s' % packageName)
                    print('%d == %d ?' % (thisVersionCode, otherVersionCode))
                if thisVersionCode != otherVersionCode:
                    toUpdate.append(details)
            except RequestError as e:
                print('Cannot fetch update Information from Playstore for {}'.format(packageName))
        return {'status': 'SUCCESS',
                'message': toUpdate}


    def remove_local_app(self, packageName):

        if not self.loggedIn:
            return {'status': 'UNAUTHORIZED'}

        if self.debug:
            print("Going to remove {}".format(packageName))

        is_same_package = lambda app: get_app_detail(app, 'packageName') == packageName
        exist_index = next((index for (index, app) in enumerate(self.currentSet) if is_same_package(app)), None)

        if None == exist_index:
            return {'status': 'ERROR'}

        filename = packageName + '.apk'
        apkPath = self.playstore_download / filename

        if not apkPath.is_file():
            return {'status': 'ERROR'}

        apkPath.unlink()
        del self.currentSet[exist_index]

        if self.debug:
            print("Removed {}".format(packageName))

        return {'status': 'SUCCESS'}
