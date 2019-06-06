#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides unit tests to verify that the FileStore code works.
"""

from __future__ import absolute_import
from hashlib import sha256
from ipaplatform.paths import paths

try:
    # install subpackages are not shipped with wheels
    from ipalib.install import sysrestore
    from ipalib.install.sysrestore import SYSRESTORE_INDEXFILE as INDEX
    from ipalib.install.sysrestore import SYSRESTORE_MAX_INDEX as MAX_INDEX
    from ipalib.install.sysrestore import SYSRESTORE_PATH_INDEX as PATH_INDEX
    from ipalib.install.sysrestore import SYSRESTORE_SEP as SEP
except ImportError:
    INDEX = MAX_INDEX = PATH_INDEX = SEP = None

import collections
import filecmp
import os
import pytest
import shutil
import six
import uuid

# pylint: disable=import-error
if six.PY3:
    # The SafeConfigParser class has been renamed to ConfigParser in Py3
    from configparser import ConfigParser as SafeConfigParser
    from configparser import MissingSectionHeaderError
else:
    from ConfigParser import SafeConfigParser
    from ConfigParser import MissingSectionHeaderError
# pylint: enable=import-error

# install subpackages are not shipped with wheels
pytestmark = [pytest.mark.needs_install_package, pytest.mark.tier0]

STORE_ROOT_DIR = os.path.join(paths.TMP, "sysrestore")
STORE_DIR = os.path.join(STORE_ROOT_DIR, str(uuid.uuid4()))
SOURCE_DIR = os.path.join(paths.TMP, "sourcedir")


# helpers
def backuped_name(path):
    """
    Return an expected internal name of a file being backuped to filestore
    """
    backupfile = os.path.basename(path)
    with open(path, 'rb') as f:
        cont_hash = sha256(f.read()).hexdigest()
    return "{hexhash}-{bcppath}".format(
        hexhash=cont_hash, bcppath=backupfile
    )


def mkdir_store():
    try:
        shutil.rmtree(STORE_DIR)
    except FileNotFoundError:
        pass
    os.makedirs(STORE_DIR)
    return STORE_DIR


def mkdir_source():
    try:
        shutil.rmtree(SOURCE_DIR)
    except FileNotFoundError:
        pass
    os.makedirs(SOURCE_DIR)
    return SOURCE_DIR


def mkfile_source(sourcefile="sourcepath", content="content"):
    sourcepath = os.path.join(SOURCE_DIR, sourcefile)
    with open(sourcepath, "w") as f:
        f.write(content)
    return sourcepath


def setup_module(module):
    if os.path.isfile(os.path.join(paths.TMP, INDEX)):
        pytest.fail("Default filestore index file is already present. "
                    "These tests may break IPA installation.")
    try:
        shutil.rmtree(STORE_ROOT_DIR)
    except FileNotFoundError:
        pass


def setup_function(function):
    try:
        os.unlink(os.path.join(paths.TMP, INDEX))
    except FileNotFoundError:
        pass
    mkdir_store()
    mkdir_source()


def idf(val):
    if not val:
        return "@default"
    else:
        return "@" + val


@pytest.fixture(params=["", os.path.join(SOURCE_DIR, "newpath")], ids=idf)
def newpath(request):
    return request.param


@pytest.fixture(params=["", "../relative/"], ids=idf)
def nonabs_path(request):
    return request.param


@pytest.fixture(params=["", INDEX], ids=idf)
def store_index(request):
    return request.param


@pytest.fixture(params=["", STORE_DIR], ids=idf)
def store_dir(request):
    return request.param


@pytest.fixture
def index_kwargs(store_dir, store_index):
    kwargs = {}
    if store_dir:
        kwargs["path"] = store_dir

    if store_index:
        kwargs["index_file"] = store_index
    return kwargs


@pytest.fixture
def hasfile_kwargs():
    kwargs = {}
    kwargs["path"] = "testpath"
    return kwargs


@pytest.fixture
def backup_kwargs():
    kwargs = {}
    return kwargs


@pytest.fixture
def restore_kwargs(newpath):
    kwargs = {}
    if newpath:
        kwargs["new_path"] = newpath
    return kwargs


@pytest.fixture
def untrack_kwargs():
    kwargs = {}
    kwargs["path"] = "/oldpath"
    return kwargs


@pytest.fixture
def index_path(store_dir, store_index):
    if store_dir:
        expected_path = store_dir
    else:
        expected_path = paths.TMP

    if store_index:
        expected_index = store_index
    else:
        expected_index = INDEX
    expected_indexpath = os.path.join(expected_path, expected_index)
    return expected_indexpath


@pytest.fixture
def fstore():
    fstore = sysrestore.FileStore(path=STORE_DIR)
    return fstore


def test_create_new(index_kwargs):
    """
    Condition: new (not existing before) filestore.
    Expected result: there should be no files within the store.
    """
    fstore = sysrestore.FileStore(**index_kwargs)
    assert not fstore.files


def test_create_empty_existing(index_path, index_kwargs):
    """
    Condition: existing but empty filestore
    Expected result: there should be no files within the store.
    """
    with open(index_path, "w") as f:
        f.write("")
    fstore = sysrestore.FileStore(**index_kwargs)
    assert not fstore.files


def test_create_no_headers(index_path, index_kwargs):
    """
    Condition: existing filestore but having no headers
    Expected result: there should be an exception.
    """
    fstore = None
    with open(index_path, "w") as f:
        f.write("noheaders")

    with pytest.raises(MissingSectionHeaderError,
                       message="Attempting to parse a config file which has"
                               "no section headers should raise an exception"
                       ):
        fstore = sysrestore.FileStore(**index_kwargs)

    assert fstore is None


def test_create_wrong_header(index_path, index_kwargs):
    """
    Condition: existing filestore but having wrong headers
    Expected result: there should be no files within the store.
    """
    p = SafeConfigParser()
    p.read_dict(
        collections.OrderedDict([
            ("wrongheader",
             collections.OrderedDict([
                 ("key", "value"),
             ])),
        ])
    )
    with open(index_path, "w") as f:
        p.write(f)
    fstore = sysrestore.FileStore(**index_kwargs)
    assert not fstore.files


def test_create_broken_store(index_path, index_kwargs):
    """
    Condition: existing filestore but having broken state
    Expected result: there should be an exception
    """
    p = SafeConfigParser()
    # make key name case sensitive
    p.optionxform = str

    expected_files = collections.OrderedDict([
        ("key", SEP * (MAX_INDEX - 1)),
    ])
    p.read_dict(
        collections.OrderedDict([
            (sysrestore.SYSRESTORE_SECTION, expected_files),
        ])
    )

    with open(index_path, "w") as f:
        p.write(f)

    fstore = None
    with pytest.raises(ValueError,
                       message="Attempting to load FileStore with broken value"
                               " should raise exception"
                       ) as error:
        fstore = sysrestore.FileStore(**index_kwargs)
    assert str(error.value) == "Broken store {0}".format(index_path)
    assert fstore is None


def test_create(index_path, index_kwargs):
    """
    Condition: existing filestore with files within
    Expected result: successful creation of filestore
    """
    p = SafeConfigParser()
    # make key name case sensitive
    p.optionxform = str

    expected_files = collections.OrderedDict([
        ("key", SEP * MAX_INDEX),
    ])
    p.read_dict(
        collections.OrderedDict([
            (sysrestore.SYSRESTORE_SECTION, expected_files),
        ])
    )

    with open(index_path, "w") as f:
        p.write(f)

    fstore = sysrestore.FileStore(**index_kwargs)
    assert fstore.files == expected_files


def test_save_empty(fstore):
    """
    Condition: cleared filestore
    Expected result: lack of store index
    """
    fstore.files.clear()
    # if files is an empty dict then store should be removed
    fstore.save()
    assert not os.path.isfile(fstore._index)


def test_save_broken_store(fstore):
    """
    Condition: filestore with broken state
    Expected result: there should be an exception
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * (MAX_INDEX - 1)),
    ])

    with pytest.raises(ValueError,
                       message="Attempting to save FileStore with broken value"
                               " should raise ValueError exception"
                       ) as error:
        fstore.save()
    assert str(error.value) == "Broken store {0}".format(fstore._index)
    assert not os.path.isfile(fstore._index)


def test_save(fstore):
    """
    Condition: filestore with files within
    Expected result: successful saving to store index
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * MAX_INDEX),
    ])
    fstore.save()

    p = SafeConfigParser()
    p.optionxform = str
    p.read(fstore._index)

    expected_files = collections.OrderedDict()
    for section in p.sections():
        for (key, value) in p.items(section):
            expected_files[key] = value

    assert fstore.files == expected_files


def test_backup_not_abs(nonabs_path, backup_kwargs, fstore):
    """
    Condition: path to be backuped is empty or non-absolute
    Expected result: there should be an exception
    """
    backup_kwargs["path"] = nonabs_path
    with pytest.raises(ValueError,
                       message="Attempting to backup empty or relative "
                               "path should raise an exception"
                       ) as error:
        fstore.backup_file(**backup_kwargs)
    assert str(error.value) == "Absolute path required"
    assert not os.listdir(STORE_DIR)


def test_backup_file_not_exist(backup_kwargs, fstore):
    """
    Condition: path to be backuped does not exist
    Expected result: there should be no file in the store
    """
    backup_kwargs["path"] = "/notexisted"

    fstore.backup_file(**backup_kwargs)
    assert not os.listdir(STORE_DIR)


def test_backup_dir(backup_kwargs, fstore):
    """
    Condition: path to be backuped is directory
    Expected result: there should be an exception
    """
    backup_kwargs["path"] = SOURCE_DIR

    with pytest.raises(ValueError,
                       message="Attempting to backup a non-regular file "
                               "should raise an exception"
                       ) as error:
        fstore.backup_file(**backup_kwargs)
    assert str(error.value) == "Regular file required"
    assert not os.listdir(STORE_DIR)


def test_backup_broken_store(backup_kwargs, fstore):
    """
    Condition: filestore with broken state
    Expected result: there should be an exception
    """
    sourcepath = mkfile_source()
    backup_kwargs["path"] = sourcepath

    fstore.files = collections.OrderedDict([
        ("key", SEP * (MAX_INDEX - 1)),
    ])

    with pytest.raises(ValueError,
                       message="Attempting to backup file into broken "
                               "store should raise an exception") as error:
        fstore.backup_file(**backup_kwargs)
    assert str(error.value) == "Broken store {0}".format(fstore._index)
    assert not os.listdir(STORE_DIR)


def test_backup(backup_kwargs, fstore):
    """
    Condition: new filestore
    Expected result: successful backup of file
    """
    sourcepath = mkfile_source()
    backup_kwargs["path"] = sourcepath
    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode

    template = '{stats.st_mode},{stats.st_uid},{stats.st_gid},{path}'
    value = template.format(stats=expected_stat, path=sourcepath)
    expected_files = collections.OrderedDict()
    expected_files[backuped_name(sourcepath)] = value

    fstore.backup_file(**backup_kwargs)
    assert fstore.files == expected_files

    backupfile = os.path.join(STORE_DIR, backuped_name(sourcepath))
    actual_stat = os.lstat(backupfile)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    # check content
    assert filecmp.cmp(sourcepath, backupfile, shallow=False)


def test_backup_same_file(backup_kwargs, fstore):
    """
    Condition: new filestore with the same file within
    Expected result: no backup of file, no store changes
    """
    sourcepath = mkfile_source()
    backup_kwargs["path"] = sourcepath

    fstore.backup_file(**backup_kwargs)
    backupfile = os.path.join(STORE_DIR, backuped_name(sourcepath))
    expected_stat = os.lstat(backupfile)
    expected_mode = expected_stat.st_mode
    expected_files = collections.OrderedDict(fstore.files)

    # repeat backup
    fstore.backup_file(**backup_kwargs)
    actual_stat = os.lstat(backupfile)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    assert fstore.files == expected_files


def test_backup_same_filename(backup_kwargs, fstore):
    """
    Condition: source file has been already backuped, but the content
    is different. Updated file should be appended to the filestore.
    Expected result: successful backup; ordered store
    """
    sourcepath = mkfile_source()
    backup_kwargs["path"] = sourcepath
    expected_stat = os.lstat(sourcepath)
    template = '{stats.st_mode},{stats.st_uid},{stats.st_gid},{path}'
    value = template.format(stats=expected_stat, path=sourcepath)
    expected_files = collections.OrderedDict()
    expected_files[backuped_name(sourcepath)] = value

    fstore.backup_file(**backup_kwargs)

    # overwrite source
    sourcepath = mkfile_source(content="overwrite_content")
    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode
    value = template.format(stats=expected_stat, path=sourcepath)
    expected_files[backuped_name(sourcepath)] = value

    fstore.backup_file(**backup_kwargs)
    # check an internal state of store
    assert len(fstore.files) == 2
    assert fstore.files == expected_files

    backupfile = os.path.join(STORE_DIR, backuped_name(sourcepath))
    actual_stat = os.lstat(backupfile)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    # check content
    assert filecmp.cmp(sourcepath, backupfile, shallow=False)


def test_has_file_empty_store(hasfile_kwargs, fstore):
    """
    Condition: new filestore without files within
    Expected result: filestore has no file
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * MAX_INDEX),
    ])
    assert not fstore.has_file(**hasfile_kwargs)


def test_has_file_broken_store(hasfile_kwargs, fstore):
    """
    Condition: new filestore with broken state
    Expected result: there should be an exception
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * (MAX_INDEX - 1)),
    ])
    with pytest.raises(ValueError,
                       message="Attempting to read from broken store "
                               "should raise an exception") as error:
        fstore.has_file(**hasfile_kwargs)
    assert str(error.value) == "Broken store {0}".format(fstore._index)


def test_has_file_no_file(hasfile_kwargs, fstore):
    """
    Condition: filestore with files within, but has not a given one
    Expected result: filestore has no file
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * MAX_INDEX),
    ])
    assert not fstore.has_file(**hasfile_kwargs)


def test_has_file(hasfile_kwargs, fstore):
    """
    Condition: filestore with files within
    Expected result: filestore has file
    """
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = hasfile_kwargs["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    assert fstore.has_file(**hasfile_kwargs)


def test_restore_not_abs(nonabs_path, restore_kwargs, fstore):
    """
    Condition: path to be restored is empty or relative
    Expected result: there should be an exception
    """
    restore_kwargs["path"] = nonabs_path
    with pytest.raises(ValueError,
                       message="Attempting to restore empty or non-absolute "
                               "path should raise an exception"
                       ) as error:
        fstore.restore_file(**restore_kwargs)
    assert str(error.value) == "Absolute path required"
    assert not os.listdir(SOURCE_DIR)


def test_restore_not_abs_new(nonabs_path, fstore):
    """
    Condition: new path to be restored to is empty or relative
    Expected result: there should be an exception
    """
    kwargs = {"path": "/oldpath", "new_path": nonabs_path}

    with pytest.raises(ValueError,
                       message="Attempting to restore to a non-absolute "
                               "path should raise an exception"
                       ) as error:
        fstore.restore_file(**kwargs)
    assert str(error.value) == "Absolute new path required"
    assert not os.listdir(SOURCE_DIR)


def test_restore_broken_store(restore_kwargs, fstore):
    """
    Condition: filestore with a broken state
    Expected result: there should be an exception
    """
    restore_kwargs["path"] = "/oldpath"
    fstore.files = collections.OrderedDict([
        ("key", SEP * (MAX_INDEX - 1)),
    ])
    with pytest.raises(ValueError,
                       message="Attempting to restore from broken store "
                               "should raise an exception") as error:
        fstore.restore_file(**restore_kwargs)
    assert str(error.value) == "Broken store {0}".format(fstore._index)
    assert not os.listdir(SOURCE_DIR)


def test_restore_no_filename(restore_kwargs, fstore):
    """
    Condition: filestore with empty key
    Expected result: there should be an exception
    """
    restore_kwargs["path"] = "/oldpath"
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = restore_kwargs["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("", value),
    ])
    with pytest.raises(ValueError,
                       message="Attempting to restore a file "
                               "without name should raise an exception"
                       ) as error:
        fstore.restore_file(**restore_kwargs)
    assert str(error.value) == "No such file name in the index"
    assert not os.listdir(SOURCE_DIR)


def test_restore_no_filepath(restore_kwargs, fstore):
    """
    Condition: filestore with empty file path
    Expected result: there should be an exception
    """
    restore_kwargs["path"] = "/oldpath"
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = "nopath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    with pytest.raises(ValueError,
                       message="Attempting to restore a file "
                               "without path should raise an exception"
                       ) as error:
        fstore.restore_file(**restore_kwargs)
    assert str(error.value) == "No such file name in the index"
    assert not os.listdir(SOURCE_DIR)


def test_restore_no_backup(restore_kwargs, fstore):
    """
    Condition: filestore with missing file
    Expected result: the restoration should fail
    """
    restore_kwargs["path"] = "/oldpath"
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = restore_kwargs["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("/notexisted", value),
    ])
    assert not fstore.restore_file(**restore_kwargs)
    assert not os.listdir(SOURCE_DIR)


def test_restore_file(restore_kwargs, fstore):
    """
    Condition: filestore with backuped file within
    Expected result: successful restoration of file
    """
    sourcepath = mkfile_source()
    restore_kwargs["path"] = sourcepath
    restorepath = restore_kwargs.get("new_path")
    if restorepath is None:
        restorepath = sourcepath

    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode

    bkwargs = dict(restore_kwargs)
    try:
        del bkwargs["new_path"]
    except KeyError:
        pass
    fstore.backup_file(**bkwargs)
    # do not remove because it is used for content compare
    bakfile = sourcepath + ".bak"
    os.rename(sourcepath, bakfile)
    assert fstore.restore_file(**restore_kwargs)
    assert not fstore.files

    actual_stat = os.lstat(restorepath)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    assert actual_stat.st_uid == expected_stat.st_uid
    assert actual_stat.st_gid == expected_stat.st_gid
    # check content
    assert filecmp.cmp(restorepath, bakfile, shallow=False)

    assert not os.listdir(STORE_DIR)


def test_restore_stacked_backup(newpath, fstore):
    """
    Condition: filestore with backuped n-times file within
    Expected result: successful restoration of file
    """
    NUM_ITERS = 10
    kwargs = {}
    backups = []

    if newpath:
        kwargs["new_path"] = newpath

    sourcepath = mkfile_source()
    kwargs["path"] = sourcepath
    bkwargs = dict(kwargs)
    try:
        del bkwargs["new_path"]
    except KeyError:
        pass

    # create stack of backups for file with same name
    for num in range(NUM_ITERS):
        sourcepath = mkfile_source(content="content" + str(num))
        kwargs["path"] = sourcepath

        expected_stat = os.lstat(sourcepath)

        fstore.backup_file(**bkwargs)
        # do not remove because it is used for content compare
        backups.append([backuped_name(sourcepath), expected_stat])
        bakfile = sourcepath + ".bak" + str(num)
        os.rename(sourcepath, bakfile)

    # restore stack of backups
    for num in reversed(range(NUM_ITERS)):
        (expected_backupfile, expected_stat) = backups[num]
        expected_path = os.path.join(STORE_DIR, expected_backupfile)
        assert fstore.restore_file(**kwargs)
        assert expected_backupfile not in fstore.files
        assert not os.path.exists(expected_path)

        expected_mode = expected_stat.st_mode
        if newpath:
            restorepath = kwargs["new_path"]
        else:
            restorepath = sourcepath
        actual_stat = os.lstat(restorepath)
        actual_mode = actual_stat.st_mode
        assert oct(actual_mode) == oct(expected_mode)
        assert actual_stat.st_uid == expected_stat.st_uid
        assert actual_stat.st_gid == expected_stat.st_gid
        # check content
        bakfile = sourcepath + ".bak" + str(num)
        assert filecmp.cmp(restorepath, bakfile, shallow=False)

    assert not fstore.files
    assert not os.listdir(STORE_DIR)


def test_restore_all_no_files(fstore):
    """
    Condition: empty filestore
    Expected result: the restoration should fail
    """
    fstore.files.clear()
    assert not fstore.restore_all_files()


def test_restore_all_files(fstore):
    """
    Condition: filestore with n different files
    Expected result: successful restoration of files
    """
    NUM_BACKUPS = 10
    backups = []

    # create backups
    for num in range(NUM_BACKUPS):
        sourcefile = "sourcefile" + str(num)
        sourcepath = mkfile_source(sourcefile, content="content" + str(num))
        expected_stat = os.lstat(sourcepath)

        fstore.backup_file(path=sourcepath)
        # do not remove because it is used for content compare
        backups.append([sourcepath, expected_stat])
        bakfile = sourcepath + ".bak"
        os.rename(sourcepath, bakfile)

    assert fstore.restore_all_files()
    assert not fstore.files
    assert not os.listdir(STORE_DIR)

    for (sourcepath, expected_stat) in backups:
        expected_mode = expected_stat.st_mode
        restorepath = sourcepath
        actual_stat = os.lstat(restorepath)
        actual_mode = actual_stat.st_mode
        assert oct(actual_mode) == oct(expected_mode)
        assert actual_stat.st_uid == expected_stat.st_uid
        assert actual_stat.st_gid == expected_stat.st_gid
        # check content
        bakfile = sourcepath + ".bak"
        assert filecmp.cmp(restorepath, bakfile, shallow=False)


def test_restore_all_file(fstore):
    """
    Condition: filestore with backuped n-times file within
    Expected result: successful restoration of file
    """
    NUM_BACKUPS = 10
    sourcepath = mkfile_source()
    kwargs = {"path": sourcepath}
    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode
    bakfile = sourcepath + ".bak"
    shutil.copy2(sourcepath, bakfile)
    fstore.backup_file(**kwargs)

    # create backups
    for num in range(NUM_BACKUPS):
        mkfile_source(content="content" + str(num))
        fstore.backup_file(**kwargs)

    fstore.restore_all_files()
    assert not fstore.files
    assert not os.listdir(STORE_DIR)

    actual_stat = os.lstat(sourcepath)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    assert actual_stat.st_uid == expected_stat.st_uid
    assert actual_stat.st_gid == expected_stat.st_gid
    # check content
    assert filecmp.cmp(sourcepath, bakfile, shallow=False)


def test_has_files_no_files(fstore):
    """
    Condition: empty filestore
    Expected result: has not files
    """
    fstore.files.clear()
    assert not fstore.has_files()


def test_has_files(fstore):
    """
    Condition: filestore with files within
    Expected result: has files
    """
    fstore.files.clear()
    value = SEP * MAX_INDEX
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    assert fstore.has_files()


def test_untrack_file_not_abs(nonabs_path, untrack_kwargs, fstore):
    """
    Condition: path to be untracked is empty or relative
    Expected result: there should be an exception
    """
    untrack_kwargs["path"] = nonabs_path

    with pytest.raises(ValueError,
                       message="Attempting to untrack file with relative "
                               "path should raise an exception"
                       ) as error:
        fstore.untrack_file(**untrack_kwargs)
    assert str(error.value) == "Absolute path required"


def test_untrack_broken_store(untrack_kwargs, fstore):
    """
    Condition: filestore with broken state
    Expected result: there should be an exception
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * (MAX_INDEX - 1)),
    ])

    with pytest.raises(ValueError,
                       message="Attempting to untrack file from broken "
                               "store should raise an exception") as error:
        fstore.untrack_file(**untrack_kwargs)
    assert str(error.value) == "Broken store {0}".format(fstore._index)


def test_untrack_no_filename(untrack_kwargs, fstore):
    """
    Condition: filestore without filename
    Expected result: there should be an exception
    """
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = untrack_kwargs["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("", value),
    ])
    with pytest.raises(ValueError,
                       message="Attempting to untrack a file "
                               "without name should raise an exception"
                       ) as error:
        fstore.untrack_file(**untrack_kwargs)
    assert str(error.value) == "No such file name in the index"


def test_untrack_no_filepath(untrack_kwargs, fstore):
    """
    Condition: filestore without filepath
    Expected result: there should be an exception
    """
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = "nopath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    with pytest.raises(ValueError,
                       message="Attempting to untrack a file "
                               "without path should raise an exception"
                       ) as error:
        fstore.untrack_file(**untrack_kwargs)
    assert str(error.value) == "No such file name in the index"


def test_untrack_no_backup(untrack_kwargs, fstore):
    """
    Condition: filestore without backup
    Expected result: untracking should fail
    """
    value = SEP * MAX_INDEX
    parts = value.split(SEP)
    parts[PATH_INDEX] = untrack_kwargs["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("/notexisted", value),
    ])
    assert not fstore.untrack_file(**untrack_kwargs)


def test_untrack(untrack_kwargs, fstore):
    """
    Condition: filestore with files within
    Expected result: successful untracking
    """
    sourcepath = mkfile_source()
    untrack_kwargs["path"] = sourcepath

    fstore.backup_file(**untrack_kwargs)
    assert fstore.untrack_file(**untrack_kwargs)
    assert not fstore.files
    assert not os.listdir(STORE_DIR)


def test_untrack_stacked_backup(fstore):
    """
    Condition: filestore with stacked backup of file
    Expected result: successful untracking
    """
    NUM_ITERS = 10
    kwargs = {}
    backups = []

    sourcepath = mkfile_source()
    kwargs["path"] = sourcepath

    for num in range(NUM_ITERS):
        mkfile_source(content="content" + str(num))
        fstore.backup_file(**kwargs)
        backups.append(os.path.join(STORE_DIR, backuped_name(sourcepath)))

    # untrack stack of backups
    for num in reversed(range(NUM_ITERS)):
        expected_backupfile = backups[num]
        assert fstore.untrack_file(**kwargs)
        assert not os.path.exists(expected_backupfile)

    assert not fstore.files
    assert not os.listdir(STORE_DIR)
