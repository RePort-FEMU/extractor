#!/usr/bin/env python

"""
Module that performs extraction. For usage, refer to documentation for the class
'Extractor'. This module can also be executed directly,
e.g. 'extractor.py <input> <output>'.
"""

import argparse
import hashlib
import multiprocessing
import os
from stat import S_ISREG
import shutil
import tempfile
import traceback

import magic

from binwalkInterface import runBinwalk

headerSignatures = ["binhdr", "chk", "dlob", "jboot_arm", "jboot_sch2", "jboot_stag", "luks", "packimg", "rtk", "seama", "tplink"]
kernelSignatures = ["linux_arm64_boot_image", "linux_boot_image", "linux_kernel", "wind_kernel"]
rootfsSignatures = ["cramfs", "ext", "fat", "jffs2", "romfs", "yaffs", "apfs", "squashfs", "btrfs"]
ubiSignatures    = ["ubi", "ubifs"]
compressedSignatures = ["zstd", "zlib", "xz", "gzip", "bzip2", "lzop", "lzma", "lzfse", "lz4", "compressd"]
archiveSignatures = ["zip", "rar", "tarball", "cab", "cpio", "7zip"]

class Extractor(object):
    """
    Class that extracts kernels and filesystems from firmware images, given an
    input file or directory and output directory.
    """

    # Directories that define the root of a UNIX filesystem, and the
    # appropriate threshold condition
    UNIX_DIRS = ["bin", "etc", "dev", "home", "lib", "mnt", "opt", "root",
                 "run", "sbin", "tmp", "usr", "var"]
    UNIX_THRESHOLD = 4

    # Lock to prevent concurrent access to visited set. Unfortunately, must be
    # static because it cannot be pickled or passed as instance attribute.
    visited_lock = multiprocessing.Lock()

    def __init__(self, indir, outdir=None, rootfs=True, kernel=True,
                 numproc=True, server=None, brand=None, port=5432, quiet=False):
        # Input firmware update file or directory
        self._input = os.path.abspath(indir)
        # Output firmware directory
        self.output_dir = os.path.abspath(outdir) if outdir else None

        # Whether to attempt to extract kernel
        self.do_kernel = kernel

        # Whether to attempt to extract root filesystem
        self.do_rootfs = rootfs

        # Brand of the firmware
        self.brand = brand

        # Hostname of SQL server
        self.database = server
        self.port = port

        # Worker pool.
        self._pool = multiprocessing.Pool() if numproc else None

        # Set containing MD5 checksums of visited items
        self.visited = set()

        # List containing tagged items to extract as 2-tuple: (tag [e.g. MD5],
        # path)
        self._list = list()
        
        self.quiet = quiet

    def __getstate__(self):
        """
        Eliminate attributes that should not be pickled.
        """
        self_dict = self.__dict__.copy()
        del self_dict["_pool"]
        del self_dict["_list"]
        return self_dict

    @staticmethod
    def io_dd(indir, offset, size, outdir):
        """
        Given a path to a target file, extract size bytes from specified offset
        to given output file.
        """
        if not size:
            return

        with open(indir, "rb") as ifp:
            with open(outdir, "wb") as ofp:
                ifp.seek(offset, 0)
                ofp.write(ifp.read(size))

    @staticmethod
    def magic(indata, mime=False):
        """
        Performs file magic while maintaining compatibility with different
        libraries.
        """

        try:
            if mime:
                mymagic = magic.open(magic.MAGIC_MIME_TYPE)
            else:
                mymagic = magic.open(magic.MAGIC_NONE)
            mymagic.load()
        except AttributeError:
            mymagic = magic.Magic(mime)
            mymagic.file = mymagic.from_file
        return mymagic.file(indata)

    @staticmethod
    def io_md5(target):
        """
        Performs MD5 with a block size of 64kb.
        """
        blocksize = 65536
        hasher = hashlib.md5()

        stat = os.stat(target)
        if not S_ISREG(stat.st_mode):
            hasher.update(target.encode('utf-8'))
        else:
            with open(target, 'rb') as ifp:
                buf = ifp.read(blocksize)
                while buf:
                    hasher.update(buf)
                    buf = ifp.read(blocksize)
        return hasher.hexdigest()

    @staticmethod
    def io_rm(target):
        """
        Attempts to recursively delete a directory.
        """
        shutil.rmtree(target, ignore_errors=False, onexc=Extractor._io_err)

    @staticmethod
    def _io_err(function, path, excinfo):
        """
        Internal function used by '_rm' to print out errors.
        """
        print(("!! %s: Cannot delete %s!\n%s" % (function, path, excinfo)))

    @staticmethod
    def io_find_rootfs(start, recurse=True):
        """
        Attempts to find a Linux root directory.
        """

        # Recurse into single directory chains, e.g. jffs2-root/fs_1/.../
        path = start
        while (len(os.listdir(path)) == 1 and
               os.path.isdir(os.path.join(path, os.listdir(path)[0]))):
            path = os.path.join(path, os.listdir(path)[0])

        # count number of unix-like directories
        count = 0
        for subdir in os.listdir(path):
            if subdir in Extractor.UNIX_DIRS and \
                os.path.isdir(os.path.join(path, subdir)):
                count += 1

        # check for extracted filesystem, otherwise update queue
        if count >= Extractor.UNIX_THRESHOLD:
            return (True, path)

        # in some cases, multiple filesystems may be extracted, so recurse to
        # find best one
        if recurse:
            for subdir in os.listdir(path):
                if os.path.isdir(os.path.join(path, subdir)):
                    res = Extractor.io_find_rootfs(os.path.join(path, subdir),
                                                   False)
                    if res[0]:
                        return res

        return (False, start)

    def extract(self) -> list[dict[str, bool | str | None]]:
        """
        Perform extraction of firmware updates from input to tarballs in output
        directory using a thread pool.
        """
        if os.path.isdir(self._input):
            for path, _, files in os.walk(self._input):
                for item in files:
                    self._list.append(os.path.join(path, item))
        elif os.path.isfile(self._input):
            self._list.append(self._input)
        else:
            print("!! Cannot read file: %s" % (self._input,))

        if self.output_dir and not os.path.isdir(self.output_dir):
            os.makedirs(self.output_dir)

        results = []
        if self._pool:
            # Use starmap to collect results from _extract_item
            mapped = self._pool.map(self._extract_item, self._list)
            for res in mapped:
                    results.append(res)
        else:
            for item in self._list:
                res = self._extract_item(item)
                results.append(res)
        
        return results

    def _extract_item(self, path):
        """
        Wrapper function that creates an ExtractionItem and calls the extract()
        method.
        """

        return ExtractionItem(self, path, 0).extract()

class ExtractionItem(object):
    """
    Class that encapsulates the state of a single item that is being extracted.
    """

    # Maximum recursion breadth and depth
    RECURSION_BREADTH = 5
    RECURSION_DEPTH = 3

    def __init__(self, extractor, path, depth, tag=None):
        # Temporary directory
        self.temp = None

        # Recursion depth counter
        self.depth = depth

        # Reference to parent extractor object
        self.extractor = extractor

        # File path
        self.item = path

        # Database connection
        if self.extractor.database:
            import psycopg2
            try:
                self.database = psycopg2.connect(database="firmware",
                                                user="femu",
                                                password="femu",
                                                host=self.extractor.database,
                                                port=self.extractor.port)
            except Exception:
                self.database = None
                print("!! Cannot connect to database %s:%d!" % \
                        (self.extractor.database, self.extractor.port))
        else:
            self.database = None

        # Checksum
        self.checksum = Extractor.io_md5(path)

        # Tag
        self.tag = tag if tag else self.generate_tag()

        # Output file path and filename prefix
        self.output = os.path.join(self.extractor.output_dir, self.tag) if \
                                   self.extractor.output_dir else None

        # Status, with terminate indicating early termination for this item
        self.terminate = False
        self.status = (False, False)
        self.update_status()

    def __del__(self):
        if self.database:
            self.database.close()

        if self.temp:
            self.printf(">> Cleaning up %s..." % self.temp)
            Extractor.io_rm(self.temp)

    def printf(self, fmt):
        """
        Prints output string with appropriate depth indentation.
        """
        if self.extractor.quiet:
            return
        print(("\t" * self.depth + fmt))

    def generate_tag(self):
        """
        Generate the filename tag.
        """
        if not self.database:
            return os.path.basename(self.item) + "_" + self.checksum

        cur = None
        image_id = None
        try:
            image_id = None
            cur = self.database.cursor()
            if self.extractor.brand:
                brand = self.extractor.brand
            else:
                brand = "unknown"
            cur.execute("SELECT id FROM brand WHERE name=%s", (brand, ))
            brand_id = cur.fetchone()
            if not brand_id:
                cur.execute("INSERT INTO brand (name) VALUES (%s) RETURNING id",
                            (brand, ))
                brand_id = cur.fetchone()
            if brand_id:
                cur.execute("SELECT id FROM image WHERE hash=%s",
                            (self.checksum, ))
                image_id = cur.fetchone()
                if not image_id:
                    cur.execute("INSERT INTO image (filename, brand_id, hash) \
                                VALUES (%s, %s, %s) RETURNING id",
                                (os.path.basename(self.item), brand_id[0],
                                 self.checksum))
                    image_id = cur.fetchone()
            self.database.commit()
        except BaseException:
            traceback.print_exc()
            self.database.rollback()
        finally:
            if cur:
                cur.close()

        if image_id:
            self.printf(">> Database Image ID: %s" % image_id[0])

        return str(image_id[0]) if \
               image_id else os.path.basename(self.item) + "_" + self.checksum

    def get_kernel_status(self):
        """
        Get the flag corresponding to the kernel status.
        """
        return self.status[0]

    def get_rootfs_status(self):
        """
        Get the flag corresponding to the root filesystem status.
        """
        return self.status[1]

    def update_status(self):
        """
        Updates the status flags using the tag to determine completion status.
        """
        kernel_done = os.path.isfile(self.get_kernel_path()) if \
            self.extractor.do_kernel and self.output else \
            not self.extractor.do_kernel
        rootfs_done = os.path.isfile(self.get_rootfs_path()) if \
            self.extractor.do_rootfs and self.output else \
            not self.extractor.do_rootfs
        self.status = (kernel_done, rootfs_done)

        if self.database and kernel_done and self.extractor.do_kernel:
            self.update_database("kernel_extracted", "True")

        if self.database and rootfs_done and self.extractor.do_rootfs:
            self.update_database("rootfs_extracted", "True")

        return self.get_status()

    def update_database(self, field, value):
        """
        Update a given field in the database.
        """
        ret = True
        if self.database:
            cur = None
            try:
                cur = self.database.cursor()
                cur.execute("UPDATE image SET " + field + "='" + value +
                            "' WHERE id=%s", (self.tag, ))
                self.database.commit()
            except BaseException:
                ret = False
                traceback.print_exc()
                self.database.rollback()
            finally:
                if cur:
                    cur.close()
        return ret

    def get_status(self):
        """
        Returns True if early terminate signaled, extraction is complete,
        otherwise False.
        """
        return True if self.terminate or all(i for i in self.status) else False

    def get_kernel_path(self):
        """
        Return the full path (including filename) to the output kernel file.
        """
        return self.output + ".kernel" if self.output else None

    def get_rootfs_path(self):
        """
        Return the full path (including filename) to the output root filesystem
        file.
        """
        return self.output + ".tar.gz" if self.output else None

    def extract(self) -> dict[str, bool | str | None]:
        """
        Perform the actual extraction of firmware updates, recursively. Returns
        True if extraction complete, otherwise False.
        """
        self.printf("\n" + self.item.encode("utf-8", "replace").decode("utf-8"))

        # check if item is complete
        if self.get_status():
            self.printf(">> Skipping: completed!")
            return {"status": True, "tag": self.tag, "kernelDone": self.get_kernel_status(),
                    "rootfsDone": self.get_rootfs_status(), "kernelPath": self.get_kernel_path(),
                    "rootfsPath": self.get_rootfs_path()}

        # check if exceeding recursion depth
        if self.depth > ExtractionItem.RECURSION_DEPTH:
            self.printf(">> Skipping: recursion depth %d" % self.depth)
            return {"status": self.get_status(), "tag": self.tag, "kernelDone": self.get_kernel_status(),
                    "rootfsDone": self.get_rootfs_status(), "kernelPath": self.get_kernel_path(),
                    "rootfsPath": self.get_rootfs_path()}

        # check if checksum is in visited set
        self.printf(">> MD5: %s" % self.checksum)
        with Extractor.visited_lock:
            if self.checksum in self.extractor.visited:
                self.printf(">> Skipping: %s..." % self.checksum)
                return {"status": self.get_status(), "tag": self.tag,
                        "kernelDone": self.get_kernel_status(),
                        "rootfsDone": self.get_rootfs_status(),
                        "kernelPath": self.get_kernel_path(),
                        "rootfsPath": self.get_rootfs_path()}
            else:
                self.extractor.visited.add(self.checksum)

        # check if filetype is blacklisted
        if self._check_blacklist():
            return {"status": self.get_status(), "tag": self.tag,
                    "kernelDone": self.get_kernel_status(),
                    "rootfsDone": self.get_rootfs_status(),
                    "kernelPath": self.get_kernel_path(),
                    "rootfsPath": self.get_rootfs_path()}

        # create working directory
        self.temp = tempfile.mkdtemp()

        try:
            self.printf(">> Tag: %s" % self.tag)
            self.printf(">> Temp: %s" % self.temp)
            self.printf(">> Status: Kernel: %s, Rootfs: %s, Do_Kernel: %s, \
                Do_Rootfs: %s" % (self.get_kernel_status(),
                                  self.get_rootfs_status(),
                                  self.extractor.do_kernel,
                                  self.extractor.do_rootfs))

            for analysis in [self._check_archive, self._check_encryption, self._check_firmware,
                             self._check_kernel, self._check_rootfs,
                             self._check_compressed]:

                # Update status only if analysis changed state
                if analysis():
                    if self.update_status():
                        self.printf(">> Skipping: completed!")
                        return {"status": True, "tag": self.tag,
                                "kernelDone": self.get_kernel_status(),
                                "rootfsDone": self.get_rootfs_status(),
                                "kernelPath": self.get_kernel_path(),
                                "rootfsPath": self.get_rootfs_path()}

        except Exception:
            traceback.print_exc()

        return {"status": False, "tag": self.tag,
                "kernelDone": self.get_kernel_status(),
                "rootfsDone": self.get_rootfs_status(),
                "kernelPath": self.get_kernel_path(),
                "rootfsPath": self.get_rootfs_path()}

    def _check_blacklist(self):
        """
        Check if this file is blacklisted for analysis based on file type.
        """
        # First, use MIME-type to exclude large categories of files
        filetype = Extractor.magic(self.item.encode("utf-8", "surrogateescape"),
                                   mime=True)
        if any(s in filetype for s in ["application/x-executable",
                                       "application/x-dosexec",
                                       "application/x-object",
                                       "application/pdf",
                                       "application/msword",
                                       "image/", "text/", "video/"]):
            self.printf(">> Skipping: %s..." % filetype)
            return True

        # Next, check for specific file types that have MIME-type
        # 'application/octet-stream'
        filetype = Extractor.magic(self.item.encode("utf-8", "surrogateescape"))
        if any(s in filetype for s in ["executable", "universal binary",
                                       "relocatable", "bytecode", "applet"]):
            self.printf(">> Skipping: %s..." % filetype)
            return True

        # Finally, check for specific file extensions that would be incorrectly
        # identified
        if self.item.endswith(".dmg"):
            self.printf(">> Skipping: %s..." % (self.item))
            return True

        return False

    def _check_archive(self):
        """
        If this file is an archive, recurse over its contents, unless it matches
        an extracted root filesystem.
        """
        return self._check_recursive(archiveSignatures)

    def _check_encryption(self):
        header = b""
        with open(self.item, "rb") as f:
            header = f.read(4)

        if header == b"SHRS":
            print(">>>> Found D-Link encrypted firmware in %s!" % (self.item))

            # Source: https://github.com/0xricksanchez/dlink-decrypt
            command = 'dd if=%s skip=1756 iflag=skip_bytes status=none | openssl aes-128-cbc -d -nopad -nosalt -K "c05fbf1936c99429ce2a0781f08d6ad8" -iv "67c6697351ff4aec29cdbaabf2fbe346" --nosalt -in /dev/stdin -out %s > /dev/null 2>&1' % (self.item, os.path.join(self.temp, "dlink_decrypt"))
            os.system(command)
            return True
        return False

    def _check_firmware(self):
        """
        If this file is of a known firmware type, directly attempt to extract
        the kernel and root filesystem.
        """
        for entry in runBinwalk(self.item, includeSignatures=headerSignatures):
            # uImage
            if "uImage header" in entry.description:
                if not self.get_kernel_status() and \
                    "OS Kernel Image" in entry.description:
                    kernel_offset = entry.offset + 64
                    kernel_size = 0

                    for stmt in entry.description.split(','):
                        if "image size:" in stmt:
                            kernel_size = int(''.join(
                                i for i in stmt if i.isdigit()), 10)

                    if kernel_size != 0 and kernel_offset + kernel_size \
                        <= os.path.getsize(self.item):
                        self.printf(">>>> %s" % entry.description)

                        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                        os.close(tmp_fd)
                        Extractor.io_dd(self.item, kernel_offset,
                                        kernel_size, tmp_path)
                        kernel = ExtractionItem(self.extractor, tmp_path,
                                                self.depth, self.tag)

                        return kernel.extract()
                # elif "RAMDisk Image" in entry.description:
                #     self.printf(">>>> %s" % entry.description)
                #     self.printf(">>>> Skipping: RAMDisk / initrd")
                #     self.terminate = True
                #     return True

            # TP-Link or TRX
            elif not self.get_kernel_status() and \
                not self.get_rootfs_status() and \
                "rootfs offset: " in entry.description and \
                "kernel offset: " in entry.description:
                kernel_offset = 0
                kernel_size = 0
                rootfs_offset = 0
                rootfs_size = 0

                for stmt in entry.description.split(','):
                    if "kernel offset:" in stmt:
                        kernel_offset = int(stmt.split(':')[1], 16)
                    elif "kernel length:" in stmt:
                        kernel_size = int(stmt.split(':')[1], 16)
                    elif "rootfs offset:" in stmt:
                        rootfs_offset = int(stmt.split(':')[1], 16)
                    elif "rootfs length:" in stmt:
                        rootfs_size = int(stmt.split(':')[1], 16)

                # compute sizes if only offsets provided
                if kernel_offset != rootfs_size and kernel_size == 0 and \
                    rootfs_size == 0:
                    kernel_size = rootfs_offset - kernel_offset
                    rootfs_size = os.path.getsize(self.item) - rootfs_offset

                # ensure that computed values are sensible
                if (kernel_size > 0 and kernel_offset + kernel_size \
                    <= os.path.getsize(self.item)) and \
                    (rootfs_size != 0 and rootfs_offset + rootfs_size \
                        <= os.path.getsize(self.item)):
                    self.printf(">>>> %s" % entry.description)

                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                    os.close(tmp_fd)
                    Extractor.io_dd(self.item, kernel_offset, kernel_size,
                                    tmp_path)
                    kernel = ExtractionItem(self.extractor, tmp_path,
                                            self.depth, self.tag)
                    kernel.extract()

                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                    os.close(tmp_fd)
                    Extractor.io_dd(self.item, rootfs_offset, rootfs_size,
                                    tmp_path)
                    rootfs = ExtractionItem(self.extractor, tmp_path,
                                            self.depth, self.tag)
                    rootfs.extract()

                    return self.update_status()
        return False

    def _check_kernel(self):
        """
        If this file contains a kernel version string, assume it is a kernel.
        Only Linux kernels are currently extracted.
        """
        if not self.get_kernel_status():
            for entry in runBinwalk(self.item, includeSignatures=kernelSignatures):
                if "kernel version" in entry.description or "Linux version" in entry.description:
                    self.update_database("kernel_version",
                                            entry.description)
                    if "Linux" in entry.description:
                        kernel_path = self.get_kernel_path()
                        if kernel_path is not None:
                            shutil.copy(self.item, kernel_path)
                        else:
                            self.extractor.do_kernel = False
                        self.printf(">>>> %s" % entry.description)
                        return True
                    # VxWorks, etc
                    else:
                        self.printf(">>>> Ignoring: %s" % entry.description)
                        return False
                return False
        return False

    def _check_rootfs(self):
        """
        If this file contains a known filesystem type, extract it.
        """

        if not self.get_rootfs_status():
            # work-around issue with binwalk signature definitions for ubi
            for entry in runBinwalk(self.item, extract=True, includeSignatures=ubiSignatures + rootfsSignatures, outputDirectory=str(self.temp)):
                if entry.extractionDetails and entry.extractionDetails.success:
                    unix = Extractor.io_find_rootfs(entry.extractionDetails.outputDir)

                    if not unix[0]:
                        return False

                    self.printf(">>>> Found Linux filesystem in %s!" % unix[1])
                    if self.output:
                        shutil.make_archive(self.output, "gztar",
                                            root_dir=unix[1])
                    else:
                        self.extractor.do_rootfs = False
                    return True
        return False

    def _check_compressed(self):
        """
        If this file appears to be compressed, decompress it and recurse over
        its contents.
        """
        return self._check_recursive(compressedSignatures)

    # treat both archived and compressed files using the same pathway. this is
    # because certain files may appear as e.g. "xz compressed data" but still
    # extract into a root filesystem.
    def _check_recursive(self, fmt):
        """
        Unified implementation for checking both "archive" and "compressed"
        items.
        """
        desc = None
        # perform extraction
        for entry in runBinwalk(self.item, extract=True, includeSignatures=fmt, outputDirectory=str(self.temp)):
            # for entry in module.results:
                # skip cpio/initrd files since they should be included with
                # kernel
                # if "cpio archive" in entry.description:
                #     self.printf(">> Skipping: cpio: %s" % entry.description)
                #     self.terminate = True
                #     return True
                # desc = entry.description
                # self.printf(">>>> %s" % entry.description)
                # break
            desc = entry.description
            if entry.extractionDetails and entry.extractionDetails.success:
                unix = Extractor.io_find_rootfs(entry.extractionDetails.outputDir)

                # check for extracted filesystem, otherwise update queue
                if unix[0]:
                    self.printf(">>>> Found Linux filesystem in %s!" % unix[1])
                    if self.output:
                        shutil.make_archive(self.output, "gztar",
                                            root_dir=unix[1])
                    else:
                        self.extractor.do_rootfs = False
                    return True
                else:
                    count = 0
                    self.printf(">> Recursing into %s ..." % entry.extractionDetails.outputDir)
                    for root, _, files in os.walk(entry.extractionDetails.outputDir):
                        # sort both descending alphabetical and increasing
                        # length
                        files.sort()
                        files.sort(key=len)

                        # handle case where original file name is restored; put
                        # it to front of queue
                        if desc and "original file name:" in desc:
                            orig = None
                            for stmt in desc.split(","):
                                if "original file name:" in stmt:
                                    orig = stmt.split("\"")[1]
                            if orig and orig in files:
                                files.remove(orig)
                                files.insert(0, orig)

                        for filename in files:
                            if count > ExtractionItem.RECURSION_BREADTH:
                                self.printf(">> Skipping: recursion breadth %d"\
                                    % ExtractionItem.RECURSION_BREADTH)
                                self.terminate = True
                                return True
                            else:
                                new_item = ExtractionItem(self.extractor,
                                                          os.path.join(root,
                                                                       filename),
                                                          self.depth + 1,
                                                          self.tag)
                                if new_item.extract()["status"]:
                                    # check that we are actually done before
                                    # performing early termination. for example,
                                    # we might decide to skip on one subitem,
                                    # but we still haven't finished
                                    if self.update_status():
                                        return True
                            count += 1
        return False

def extract(input_file, output_dir=None, filesystem=True, kernel=True,
            numproc=False, brand=None, sqlIP=None,  sqlPort=5432, quiet=False) -> list[dict[str, bool | str | None]]:
    """
    Extracts the kernel and root filesystem from a given input file or
    directory to the specified output directory.
    
    :param input_file: Path to the input file or directory.
    :param output_dir: Path to the output directory where extracted files will
        be saved. If None, no output directory is created.
    :param filesystem: Whether to extract the root filesystem.
    :param kernel: Whether to extract the kernel.
    :param numproc: Whether to use multiprocessing for extraction.
    :param brand: Brand of the firmware image.
    :param sqlIP: Hostname of the SQL server to store extraction details.
    :param sqlPort: Port of the SQL server.
    :param quiet: If True, suppresses output messages.  
    
    :return: A list of dictionaries containing extraction results, each with
        keys:
        - status: True if extraction is complete, False otherwise
        - tag: Unique identifier for the extraction item
        - kernelDone: True if kernel extraction is complete or not requested, False otherwise
        - rootfsDone: True if root filesystem extraction is complete or not requested, False otherwise
        - kernelPath: Path to the extracted kernel file, or None if not extracted
        - rootfsPath: Path to the extracted root filesystem file, or None if not extracted
    
    """
    extractor = Extractor(input_file, output_dir, filesystem, kernel, numproc,
                          sqlIP, brand, sqlPort, quiet)
    return extractor.extract()

def main():
    parser = argparse.ArgumentParser(description="Extracts filesystem and \
        kernel from Linux-based firmware images")
    parser.add_argument("input", action="store", help="Input file or directory")
    parser.add_argument("output", action="store", nargs="?", default="images",
                        help="Output directory for extracted firmware")
    parser.add_argument("-sql ", dest="sql", action="store", default=None,
                        help="Hostname of SQL server")
    parser.add_argument("-p", "--port", dest="port", action="store",
                        default=5432, type=int, help="Port of SQL server")
    parser.add_argument("-nf", dest="rootfs", action="store_false",
                        default=True, help="Disable extraction of root \
                        filesystem (may decrease extraction time)")
    parser.add_argument("-nk", dest="kernel", action="store_false",
                        default=True, help="Disable extraction of kernel \
                        (may decrease extraction time)")
    parser.add_argument("-np", dest="parallel", action="store_false",
                        default=True, help="Disable parallel operation \
                        (may increase extraction time)")
    parser.add_argument("-b", dest="brand", action="store", default=None,
                        help="Brand of the firmware image")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true",
                        default=False, help="Suppress output messages")
    result = parser.parse_args()

    extract = Extractor(result.input, result.output, result.rootfs,
                        result.kernel, result.parallel, result.sql,
                        result.brand, result.port, result.quiet)
    extract.extract()

if __name__ == "__main__":
    main()
