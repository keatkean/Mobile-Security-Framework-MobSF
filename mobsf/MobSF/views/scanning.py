# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os

from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse
from django.core.files.uploadedfile import (
    InMemoryUploadedFile,
    TemporaryUploadedFile,
)

from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.views.common.shared_func import (
    unzip_file_directory,
    zip_directory
)
from mobsf.StaticAnalyzer.views.android.static_analyzer import (
    valid_source_code
)
from mobsf.MobSF.utils import is_zip_magic_local_file

logger = logging.getLogger(__name__)
HTTP_BAD_REQUEST = 400
allowed_file_types = ('.apk', '.apks', '.xapk', '.zip', '.ipa', '.appx', '.jar', '.aar')


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])
        if not db_obj.exists():
            logger.info('Data to be saved: %s', data)
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME='',
                PACKAGE_NAME='',
                VERSION_NAME='',
                MD5=data['hash'],
                TIMESTAMP=timezone.now())
            new_db_obj.save()
    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(content, extension, istemp=False):
    """Write Uploaded File."""
    md5 = hashlib.md5()
    bfr = False
    # logger.info('Content: %s, Type of content: %s', content, type(content))
    if isinstance(content, InMemoryUploadedFile) or isinstance(content, TemporaryUploadedFile):
        bfr = True
        # Not File upload
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        # File upload
        with open(content, 'rb') as file_obj:
            for chunk in iter(lambda: file_obj.read(8192), b''):
                md5.update(chunk)
        # for chunk in content.chunks():
        # md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if istemp:
        anal_dir = os.path.join(settings.TEMP_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    else:
        if istemp:
            # Delete all files and directories in the temp directory recursively
            for root, dirs, files in os.walk(anal_dir, topdown=False):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                    except OSError as e:
                        logger.error('Error while deleting file in temp directory: %s', e)
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except OSError as e:
                        logger.error('Error while deleting directory in temp directory: %s', e)

    with open(f'{anal_dir}{md5sum}{extension}', 'wb+') as destination:
        logger.info(f'Writing to {anal_dir}{md5sum}{extension}')
        if bfr:
            content.seek(0, 0)
            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            with open(content, 'rb') as file_obj:
                for chunk in iter(lambda: file_obj.read(8192), b''):
                    destination.write(chunk)
            # for chunk in content.chunks():
            #     destination.write(chunk)
    return md5sum


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name
        self.zip_password = request.POST.get('password')
        self.data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': '',
            'scan_type': '',
            'file_name': self.file_name,
        }

    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        global apk_hash
        apk_hash = md5
        self.data['scan_type'] = 'apk'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android APK')
        return self.data

    def scan_xapk(self):
        """Android XAPK."""
        md5 = handle_uploaded_file(self.file, '.xapk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'xapk'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android XAPK base APK')
        return self.data

    def scan_apks(self):
        """Android Split APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apks'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android Split APK')
        return self.data

    def scan_jar(self):
        """Java JAR file."""
        md5 = handle_uploaded_file(self.file, '.jar')
        self.data['hash'] = md5
