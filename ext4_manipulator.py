#!/usr/bin/env python3
"""
EXT4 Metadata Manipulation Module

A specialized module for interacting with and modifying EXT4-specific metadata structures
such as inodes, extended attributes, and journal entries.

IMPORTANT: This module requires root privileges to function properly
and should only be used in authorized testing environments.
"""

import os
import sys
import datetime
import logging
import json
import struct
import binascii
import tempfile
import subprocess
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any, BinaryIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ext4_manipulation.log')
    ]
)
logger = logging.getLogger(__name__)

class EXT4FileType(Enum):
    """EXT4 file types."""
    UNKNOWN = 0x0
    REGULAR_FILE = 0x1
    DIRECTORY = 0x2
    CHARACTER_DEVICE = 0x3
    BLOCK_DEVICE = 0x4
    FIFO = 0x5
    SOCKET = 0x6
    SYMBOLIC_LINK = 0x7

class EXT4InodeFlags(Enum):
    """Flags used in EXT4 inodes."""
    SECURE_DELETION = 0x00000001
    KEEP_COPY = 0x00000002
    FILE_COMPRESSION = 0x00000004
    SYNC_UPDATES = 0x00000008
    IMMUTABLE_FILE = 0x00000010
    APPEND_ONLY = 0x00000020
    NO_DUMP = 0x00000040
    NO_ACCESS_TIME = 0x00000080
    NO_INDEX = 0x00001000
    JOURNAL_DATA = 0x00004000
    BTREE_DIR = 0x00010000
    HUGE_FILE = 0x00040000
    EXTENTS = 0x00080000
    LARGE_EA = 0x00200000
    INLINE_DATA = 0x10000000
    ENCRYPT = 0x00800000

class ExtendedAttributeName(Enum):
    """Common extended attribute namespaces."""
    USER = "user."
    SYSTEM = "system."
    SECURITY = "security."
    TRUSTED = "trusted."

class EXT4Inode:
    """Class representing an EXT4 inode."""
    
    def __init__(self, inode_data: bytes = None):
        """Initialize a new EXT4 inode object."""
        self.mode = 0
        self.uid = 0
        self.size_lo = 0
        self.atime = 0
        self.ctime = 0
        self.mtime = 0
        self.dtime = 0
        self.gid = 0
        self.links_count = 0
        self.blocks_lo = 0
        self.flags = 0
        self.version = 0
        self.block = [0] * 15  # Direct, indirect, double indirect, triple indirect blocks
        self.generation = 0
        self.file_acl = 0
        self.size_hi = 0
        self.obso_faddr = 0
        self.blocks_hi = 0
        self.i_extra_isize = 0
        self.i_checksum_hi = 0
        self.i_ctime_extra = 0
        self.i_mtime_extra = 0
        self.i_atime_extra = 0
        self.i_crtime = 0
        self.i_crtime_extra = 0
        self.i_version_hi = 0
        self.i_projid = 0
        
        if inode_data:
            self.parse(inode_data)
    
    def parse(self, data: bytes) -> None:
        """Parse raw EXT4 inode data."""
        if len(data) < 128:  # Minimum inode size for modern EXT4
            raise ValueError("Data too small to be an EXT4 inode")
        
        # Parse basic inode fields
        self.mode = struct.unpack("<H", data[0:2])[0]
        self.uid = struct.unpack("<H", data[2:4])[0]
        self.size_lo = struct.unpack("<I", data[4:8])[0]
        self.atime = struct.unpack("<I", data[8:12])[0]
        self.ctime = struct.unpack("<I", data[12:16])[0]
        self.mtime = struct.unpack("<I", data[16:20])[0]
        self.dtime = struct.unpack("<I", data[20:24])[0]
        self.gid = struct.unpack("<H", data[24:26])[0]
        self.links_count = struct.unpack("<H", data[26:28])[0]
        self.blocks_lo = struct.unpack("<I", data[28:32])[0]
        self.flags = struct.unpack("<I", data[32:36])[0]
        self.version = struct.unpack("<I", data[36:40])[0]
        
        # Block pointers
        for i in range(15):
            offset = 40 + (i * 4)
            self.block[i] = struct.unpack("<I", data[offset:offset+4])[0]
        
        # Remaining fields
        self.generation = struct.unpack("<I", data[100:104])[0]
        self.file_acl = struct.unpack("<I", data[104:108])[0]
        self.size_hi = struct.unpack("<I", data[108:112])[0]
        self.obso_faddr = struct.unpack("<I", data[112:116])[0]
        
        # Extra fields for 256-byte inodes
        if len(data) >= 156:
            self.blocks_hi = struct.unpack("<H", data[116:118])[0]
            self.i_extra_isize = struct.unpack("<H", data[128:130])[0]
            self.i_checksum_hi = struct.unpack("<H", data[130:132])[0]
            self.i_ctime_extra = struct.unpack("<I", data[132:136])[0]
            self.i_mtime_extra = struct.unpack("<I", data[136:140])[0]
            self.i_atime_extra = struct.unpack("<I", data[140:144])[0]
            self.i_crtime = struct.unpack("<I", data[144:148])[0]
            self.i_crtime_extra = struct.unpack("<I", data[148:152])[0]
            self.i_version_hi = struct.unpack("<I", data[152:156])[0]
        
        # Project ID field
        if len(data) >= 160:
            self.i_projid = struct.unpack("<I", data[156:160])[0]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert EXT4 inode to dictionary."""
        return {
            'mode': self.mode,
            'file_type': self._get_file_type(),
            'permissions': self._format_permissions(),
            'uid': self.uid,
            'gid': self.gid,
            'size': (self.size_hi << 32) | self.size_lo,
            'atime': self._format_time(self.atime),
            'ctime': self._format_time(self.ctime),
            'mtime': self._format_time(self.mtime),
            'dtime': self._format_time(self.dtime) if self.dtime else None,
            'crtime': self._format_time(self.i_crtime) if self.i_crtime else None,
            'links_count': self.links_count,
            'blocks': (self.blocks_hi << 32) | self.blocks_lo if hasattr(self, 'blocks_hi') else self.blocks_lo,
            'flags': self.flags,
            'flags_decoded': self._decode_flags(),
            'generation': self.generation,
            'file_acl': self.file_acl,
            'version': (self.i_version_hi << 32) | self.version if hasattr(self, 'i_version_hi') else self.version,
            'inode_size': 128 + (self.i_extra_isize if hasattr(self, 'i_extra_isize') else 0),
            'direct_blocks': self.block[:12],
            'indirect_block': self.block[12],
            'double_indirect_block': self.block[13],
            'triple_indirect_block': self.block[14]
        }
    
    def _get_file_type(self) -> str:
        """Get file type from mode."""
        file_type = (self.mode >> 12) & 0xF
        
        if file_type == 0x1:
            return "FIFO"
        elif file_type == 0x2:
            return "CHARACTER_DEVICE"
        elif file_type == 0x4:
            return "DIRECTORY"
        elif file_type == 0x6:
            return "BLOCK_DEVICE"
        elif file_type == 0x8:
            return "REGULAR_FILE"
        elif file_type == 0xA:
            return "SYMBOLIC_LINK"
        elif file_type == 0xC:
            return "SOCKET"
        else:
            return "UNKNOWN"
    
    def _format_permissions(self) -> str:
        """Format Unix-style permissions from mode."""
        perms = ""
        
        # User permissions
        perms += "r" if (self.mode & 0x0100) else "-"
        perms += "w" if (self.mode & 0x0080) else "-"
        perms += "x" if (self.mode & 0x0040) else "-"
        
        # Group permissions
        perms += "r" if (self.mode & 0x0020) else "-"
        perms += "w" if (self.mode & 0x0010) else "-"
        perms += "x" if (self.mode & 0x0008) else "-"
        
        # Other permissions
        perms += "r" if (self.mode & 0x0004) else "-"
        perms += "w" if (self.mode & 0x0002) else "-"
        perms += "x" if (self.mode & 0x0001) else "-"
        
        return perms
    
    def _format_time(self, timestamp: int) -> str:
        """Format Unix timestamp as ISO datetime string."""
        try:
            if timestamp == 0:
                return None
            return datetime.datetime.fromtimestamp(timestamp).isoformat()
        except:
            return f"Invalid timestamp: {timestamp}"
    
    def _decode_flags(self) -> List[str]:
        """Decode EXT4 inode flags."""
        result = []
        for flag in EXT4InodeFlags:
            if self.flags & flag.value:
                result.append(flag.name)
        return result
    
    def update_timestamps(self, 
                         atime: Optional[datetime.datetime] = None,
                         mtime: Optional[datetime.datetime] = None,
                         ctime: Optional[datetime.datetime] = None,
                         crtime: Optional[datetime.datetime] = None) -> None:
        """Update timestamps in the inode."""
        if atime:
            self.atime = int(atime.timestamp())
            if hasattr(self, 'i_atime_extra'):
                # High-precision portion (nanoseconds)
                ns = int(atime.timestamp() * 1e9) % 1000000000
                self.i_atime_extra = ns
        
        if mtime:
            self.mtime = int(mtime.timestamp())
            if hasattr(self, 'i_mtime_extra'):
                ns = int(mtime.timestamp() * 1e9) % 1000000000
                self.i_mtime_extra = ns
        
        if ctime:
            self.ctime = int(ctime.timestamp())
            if hasattr(self, 'i_ctime_extra'):
                ns = int(ctime.timestamp() * 1e9) % 1000000000
                self.i_ctime_extra = ns
        
        if crtime and hasattr(self, 'i_crtime'):
            self.i_crtime = int(crtime.timestamp())
            if hasattr(self, 'i_crtime_extra'):
                ns = int(crtime.timestamp() * 1e9) % 1000000000
                self.i_crtime_extra = ns
    
    def to_bytes(self) -> bytes:
        """Convert EXT4 inode to bytes."""
        # Determine inode size
        inode_size = 128
        if hasattr(self, 'i_extra_isize') and self.i_extra_isize > 0:
            inode_size = 128 + self.i_extra_isize
        
        # Create buffer
        data = bytearray(inode_size)
        
        # Basic fields
        struct.pack_into("<H", data, 0, self.mode)
        struct.pack_into("<H", data, 2, self.uid)
        struct.pack_into("<I", data, 4, self.size_lo)
        struct.pack_into("<I", data, 8, self.atime)
        struct.pack_into("<I", data, 12, self.ctime)
        struct.pack_into("<I", data, 16, self.mtime)
        struct.pack_into("<I", data, 20, self.dtime)
        struct.pack_into("<H", data, 24, self.gid)
        struct.pack_into("<H", data, 26, self.links_count)
        struct.pack_into("<I", data, 28, self.blocks_lo)
        struct.pack_into("<I", data, 32, self.flags)
        struct.pack_into("<I", data, 36, self.version)
        
        # Block pointers
        for i in range(15):
            offset = 40 + (i * 4)
            struct.pack_into("<I", data, offset, self.block[i])
        
        # Other fields
        struct.pack_into("<I", data, 100, self.generation)
        struct.pack_into("<I", data, 104, self.file_acl)
        struct.pack_into("<I", data, 108, self.size_hi)
        struct.pack_into("<I", data, 112, self.obso_faddr)
        
        # Extended fields
        if inode_size >= 156:
            struct.pack_into("<H", data, 116, getattr(self, 'blocks_hi', 0))
            struct.pack_into("<H", data, 128, getattr(self, 'i_extra_isize', 0))
            struct.pack_into("<H", data, 130, getattr(self, 'i_checksum_hi', 0))
            struct.pack_into("<I", data, 132, getattr(self, 'i_ctime_extra', 0))
            struct.pack_into("<I", data, 136, getattr(self, 'i_mtime_extra', 0))
            struct.pack_into("<I", data, 140, getattr(self, 'i_atime_extra', 0))
            struct.pack_into("<I", data, 144, getattr(self, 'i_crtime', 0))
            struct.pack_into("<I", data, 148, getattr(self, 'i_crtime_extra', 0))
            struct.pack_into("<I", data, 152, getattr(self, 'i_version_hi', 0))
        
        # Project ID
        if inode_size >= 160:
            struct.pack_into("<I", data, 156, getattr(self, 'i_projid', 0))
        
        return bytes(data)

class JournalBlock:
    """Class representing a journal block."""
    
    def __init__(self, block_data: bytes = None):
        """Initialize a new journal block object."""
        self.magic = 0
        self.entry_type = 0
        self.sequence = 0
        self.block_size = 0
        self.data = b''
        
        if block_data:
            self.parse(block_data)
    
    def parse(self, data: bytes) -> None:
        """Parse raw journal block data."""
        if len(data) < 12:  # Minimum header size
            raise ValueError("Data too small to be a journal block")
        
        self.magic = struct.unpack(">I", data[0:4])[0]
        self.entry_type = struct.unpack(">I", data[4:8])[0]
        self.sequence = struct.unpack(">I", data[8:12])[0]
        
        # Actual block data
        self.data = data[12:]
        
        # Determine block size
        self.block_size = len(data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert journal block to dictionary."""
        return {
            'magic': self.magic,
            'magic_hex': f"0x{self.magic:08x}",
            'entry_type': self.entry_type,
            'entry_type_name': self._get_entry_type_name(),
            'sequence': self.sequence,
            'block_size': self.block_size,
            'data_hash': self._get_data_hash()
        }
    
    def _get_entry_type_name(self) -> str:
        """Get human-readable name for entry type."""
        type_names = {
            1: "DESCRIPTOR",
            2: "COMMIT",
            3: "SUPERBLOCK_V1",
            4: "SUPERBLOCK_V2",
            5: "REVOKE"
        }
        return type_names.get(self.entry_type, f"UNKNOWN_TYPE_{self.entry_type}")
    
    def _get_data_hash(self) -> str:
        """Get hash of block data."""
        import hashlib
        return hashlib.md5(self.data).hexdigest()

class EXT4Manipulator:
    """Class for manipulating EXT4 metadata structures."""
    
    def __init__(self, device_path: str = None):
        """Initialize the EXT4 manipulator."""
        self.device_path = device_path
        self.is_root = self._check_root()
        self.debugfs_available = self._check_debugfs()
        self.e2fsprogs_available = self._check_e2fsprogs()
    
    def _check_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def _check_debugfs(self) -> bool:
        """Check if debugfs is available."""
        try:
            result = subprocess.run(['which', 'debugfs'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  text=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_e2fsprogs(self) -> bool:
        """Check if e2fsprogs tools are available."""
        try:
            result = subprocess.run(['which', 'e2fsck'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  text=True)
            return result.returncode == 0
        except:
            return False
    
    def set_device(self, device_path: str) -> bool:
        """Set the device or volume to work with."""
        if os.path.exists(device_path):
            self.device_path = device_path
            return True
        return False
    
    def read_inode(self, inode_number: int) -> Optional[EXT4Inode]:
        """Read an inode by number (simulated for educational purposes)."""
        if not self.is_root:
            logger.warning("Root privileges required to read raw inodes")
            return None
        
        if not self.device_path:
            logger.error("No device path specified")
            return None
        
        # This is a simulated implementation
        # In a real implementation, this would use debugfs or direct device access
        logger.info(f"Simulating reading inode {inode_number} from {self.device_path}")
        
        # Create a simulated inode
        inode = EXT4Inode()
        inode.mode = 0o100644  # Regular file, 644 permissions
        inode.uid = 1000
        inode.gid = 1000
        inode.size_lo = 1024
        inode.size_hi = 0
        inode.atime = int(datetime.datetime.now().timestamp())
        inode.mtime = int(datetime.datetime.now().timestamp())
        inode.ctime = int(datetime.datetime.now().timestamp())
        inode.dtime = 0
        inode.links_count = 1
        inode.blocks_lo = 2
        inode.flags = EXT4InodeFlags.EXTENTS.value  # Using extents
        inode.block[0] = 12345  # Direct block pointer
        inode.generation = 1
        inode.file_acl = 0
        
        # Extended inode fields
        inode.i_extra_isize = 28
        inode.i_crtime = int(datetime.datetime.now().timestamp())
        
        return inode
    
    def write_inode(self, inode_number: int, inode: EXT4Inode) -> bool:
        """Write an inode (simulated for educational purposes)."""
        if not self.is_root:
            logger.warning("Root privileges required to write raw inodes")
            return False
        
        if not self.device_path:
            logger.error("No device path specified")
            return False
        
        # This is a simulated implementation
        # In a real implementation, this would use direct device access
        logger.info(f"Simulating writing inode {inode_number} to {self.device_path}")
        
        # Convert inode to bytes and validate
        inode_bytes = inode.to_bytes()
        logger.info(f"Inode data size: {len(inode_bytes)} bytes")
        
        # In a real implementation, we would calculate the exact offset in the inode table
        # and write the bytes there using direct disk access
        
        return True
    
    def update_file_times(self, 
                         file_path: str, 
                         atime: Optional[datetime.datetime] = None,
                         mtime: Optional[datetime.datetime] = None,
                         ctime: Optional[datetime.datetime] = None,
                         crtime: Optional[datetime.datetime] = None) -> bool:
        """Update file times (uses touch for atime/mtime, simulates ctime/crtime)."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        success = True
        
        # For atime/mtime, we can use touch
        if atime or mtime:
            try:
                cmd = ['touch']
                
                if atime:
                    cmd.extend(['-a', f'--date=@{int(atime.timestamp())}'])
                
                if mtime:
                    cmd.extend(['-m', f'--date=@{int(mtime.timestamp())}'])
                
                cmd.append(file_path)
                
                subprocess.run(cmd, check=True)
                logger.info(f"Updated atime/mtime for {file_path}")
            except Exception as e:
                logger.error(f"Failed to update atime/mtime: {str(e)}")
                success = False
        
        # For ctime/crtime, we'd need direct inode manipulation
        if ctime or crtime:
            logger.info(f"Simulating updating ctime/crtime for {file_path}")
            
            # In a real implementation with root access, we would:
            # 1. Find the inode number for this file
            # 2. Read the inode
            # 3. Modify the timestamps
            # 4. Write the inode back
            
            if not self.is_root:
                logger.warning("Root privileges required to update ctime/crtime")
                success = False
        
        return success
    
    def get_file_extended_attributes(self, file_path: str) -> Dict[str, str]:
        """Get extended attributes for a file."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {}
        
        result = {}
        
        try:
            # Use getfattr command to get extended attributes
            cmd = ['getfattr', '-d', '-m', '-', file_path]
            output = subprocess.check_output(cmd, text=True)
            
            # Parse output
            for line in output.strip().split('\n'):
                line = line.strip()
                if '=' in line:
                    name, value = line.split('=', 1)
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]  # Remove quotes
                    result[name] = value
        
        except Exception as e:
            logger.error(f"Failed to get extended attributes: {str(e)}")
        
        return result
    
    def set_file_extended_attribute(self, file_path: str, name: str, value: str) -> bool:
        """Set an extended attribute for a file."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        try:
            # Use setfattr command to set extended attribute
            cmd = ['setfattr', '-n', name, '-v', value, file_path]
            subprocess.run(cmd, check=True)
            logger.info(f"Set extended attribute {name}={value} for {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to set extended attribute: {str(e)}")
            return False
    
    def remove_file_extended_attribute(self, file_path: str, name: str) -> bool:
        """Remove an extended attribute from a file."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        try:
            # Use setfattr command to remove extended attribute
            cmd = ['setfattr', '-x', name, file_path]
            subprocess.run(cmd, check=True)
            logger.info(f"Removed extended attribute {name} from {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to remove extended attribute: {str(e)}")
            return False
    
    def query_journal(self, max_blocks: int = 10) -> List[JournalBlock]:
        """Query the journal (simulated for educational purposes)."""
        if not self.is_root:
            logger.warning("Root privileges required to query journal")
            return []
        
        if not self.device_path:
            logger.error("No device path specified")
            return []
        
        # This is a simulated implementation
        # In a real implementation, this would use specialized tools or direct device access
        logger.info(f"Simulating querying journal on {self.device_path}")
        
        # Create some simulated journal blocks
        blocks = []
        for i in range(max_blocks):
            block = JournalBlock()
            block.magic = 0x12345678
            block.entry_type = (i % 5) + 1  # Cycle through different types
            block.sequence = 1000 + i
            block.block_size = 4096
            block.data = bytes([i & 0xFF] * 4084)  # Fixed data pattern
            blocks.append(block)
        
        return blocks
    
    def clear_journal(self) -> bool:
        """Clear the journal (simulated for educational purposes)."""
        if not self.is_root:
            logger.warning("Root privileges required to clear journal")
            return False
        
        if not self.device_path:
            logger.error("No device path specified")
            return False
        
        # This is a simulated implementation
        # In a real implementation, this would use specialized tools or direct device access
        logger.info(f"Simulating clearing journal on {self.device_path}")
        
        # Would typically involve:
        # 1. Unmounting the filesystem
        # 2. Using tune2fs to clear the journal
        # 3. Remounting the filesystem
        
        return True
    
    def get_file_flags(self, file_path: str) -> Optional[List[str]]:
        """Get file flags using lsattr."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        try:
            # Use lsattr command to get file flags
            cmd = ['lsattr', file_path]
            output = subprocess.check_output(cmd, text=True)
            
            # Parse output (format: "flags filename")
            line = output.strip().split('\n')[0]
            flags_str = line.split()[0]
            
            # Convert to flag names
            flag_map = {
                'a': 'APPEND_ONLY',
                'c': 'COMPRESSED',
                'd': 'NO_DUMP',
                'e': 'EXTENTS',
                'i': 'IMMUTABLE',
                'j': 'JOURNAL_DATA',
                's': 'SECURE_DELETION',
                't': 'NO_TAIL_MERGING',
                'u': 'UNDELETE',
                'A': 'NO_ATIME',
                'C': 'NO_COPY_ON_WRITE',
                'D': 'SYNCHRONOUS_DIRECTORY',
                'E': 'ENCRYPTED',
                'I': 'INDEXED_DIRECTORY',
                'S': 'SYNCHRONOUS_UPDATES',
                'T': 'TOP_OF_DIRECTORY'
            }
            
            result = []
            for i, c in enumerate(flags_str):
                if c != '-':  # '-' means flag not set
                    result.append(flag_map.get(c, f"UNKNOWN_{c}"))
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to get file flags: {str(e)}")
            return None
    
    def set_file_flags(self, file_path: str, flags: List[str]) -> bool:
        """Set file flags using chattr."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        # Map flag names to chattr flags
        flag_map = {
            'APPEND_ONLY': 'a',
            'COMPRESSED': 'c',
            'NO_DUMP': 'd',
            'EXTENTS': 'e',
            'IMMUTABLE': 'i',
            'JOURNAL_DATA': 'j',
            'SECURE_DELETION': 's',
            'NO_TAIL_MERGING': 't',
            'UNDELETE': 'u',
            'NO_ATIME': 'A',
            'NO_COPY_ON_WRITE': 'C',
            'SYNCHRONOUS_DIRECTORY': 'D',
            'ENCRYPTED': 'E',
            'INDEXED_DIRECTORY': 'I',
            'SYNCHRONOUS_UPDATES': 'S',
            'TOP_OF_DIRECTORY': 'T'
        }
        
        # Convert flag names to chattr format
        flag_str = ''
        for flag in flags:
            if flag in flag_map:
                flag_str += flag_map[flag]
        
        if not flag_str:
            logger.error("No valid flags specified")
            return False
        
        try:
            # Use chattr command to set file flags
            cmd = ['chattr', f'+{flag_str}', file_path]
            subprocess.run(cmd, check=True)
            logger.info(f"Set flags {flags} for {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to set file flags: {str(e)}")
            return False
    
    def clear_file_flags(self, file_path: str) -> bool:
        """Clear all file flags using chattr."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        try:
            # Get current flags
            current_flags = self.get_file_flags(file_path)
            if not current_flags:
                return True  # No flags to clear
            
            # Map flag names to chattr flags
            flag_map = {
                'APPEND_ONLY': 'a',
                'COMPRESSED': 'c',
                'NO_DUMP': 'd',
                'EXTENTS': 'e',
                'IMMUTABLE': 'i',
                'JOURNAL_DATA': 'j',
                'SECURE_DELETION': 's',
                'NO_TAIL_MERGING': 't',
                'UNDELETE': 'u',
                'NO_ATIME': 'A',
                'NO_COPY_ON_WRITE': 'C',
                'SYNCHRONOUS_DIRECTORY': 'D',
                'ENCRYPTED': 'E',
                'INDEXED_DIRECTORY': 'I',
                'SYNCHRONOUS_UPDATES': 'S',
                'TOP_OF_DIRECTORY': 'T'
            }
            
            # Convert flag names to chattr format
            flag_str = ''
            for flag in current_flags:
                if flag in flag_map:
                    flag_str += flag_map[flag]
            
            if not flag_str:
                return True  # No flags to clear
            
            # Use chattr command to clear file flags
            cmd = ['chattr', f'-{flag_str}', file_path]
            subprocess.run(cmd, check=True)
            logger.info(f"Cleared flags for {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to clear file flags: {str(e)}")
            return False

# Example usage function
def demonstrate_ext4_manipulation():
    """Demonstrate EXT4 manipulation capabilities (safely)."""
    
    # Check if running as root
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    print("EXT4 Metadata Manipulation Module - Demonstration")
    print("=" * 60)
    print(f"Running with root privileges: {'Yes' if is_root else 'No'}")
    print()
    
    if not is_root:
        print("Warning: Many operations require root privileges to work properly.")
        print("This demonstration will show simulated operations only.")
        print()
    
    # Create a manipulator
    manipulator = EXT4Manipulator()
    
    # Set device (in a real scenario, this would be a device like /dev/sda1)
    device_path = "/dev/sda1"
    manipulator.set_device(device_path)
    
    print(f"Using device: {device_path}")
    print(f"debugfs available: {manipulator.debugfs_available}")
    print(f"e2fsprogs available: {manipulator.e2fsprogs_available}")
    print()
    
    # Read an inode
    print("Reading inode (simulated)...")
    inode = manipulator.read_inode(12345)
    if inode:
        print("Inode details:")
        print(json.dumps(inode.to_dict(), indent=2))
    
    print("\n" + "=" * 60)
    
    # Query journal
    print("\nQuerying journal (simulated)...")
    blocks = manipulator.query_journal(3)
    if blocks:
        print(f"Found {len(blocks)} blocks:")
        for i, block in enumerate(blocks):
            block_dict = block.to_dict()
            print(f"- Block {i+1} - Type: {block_dict['entry_type_name']}")
            print(f"  Sequence: {block_dict['sequence']}")
            print(f"  Magic: {block_dict['magic_hex']}")
            print(f"  Data Hash: {block_dict['data_hash']}")
            print()
    
    # Demonstrate extended attributes if possible
    print("\nDemonstrating extended attributes...")
    test_file = "example.txt"
    
    # Create the file if it doesn't exist
    if not os.path.exists(test_file):
        try:
            with open(test_file, "w") as f:
                f.write("This is a test file.")
            print(f"Created test file: {test_file}")
        except:
            print(f"Could not create test file: {test_file}")
    
    if os.path.exists(test_file):
        # Get current extended attributes
        xattrs = manipulator.get_file_extended_attributes(test_file)
        print(f"Current extended attributes: {xattrs}")
        
        # Try to set an extended attribute
        print("\nAttempting to set user.example=test")
        success = manipulator.set_file_extended_attribute(test_file, "user.example", "test")
        print(f"Set attribute: {'Success' if success else 'Failed'}")
        
        # Get attributes again
        xattrs = manipulator.get_file_extended_attributes(test_file)
        print(f"Updated extended attributes: {xattrs}")
        
        # Get file flags
        print("\nGetting file flags:")
        flags = manipulator.get_file_flags(test_file)
        print(f"Current flags: {flags}")
    
    # Demonstrate timestamp modification
    print("\nModifying file timestamps...")
    if os.path.exists(test_file):
        print("Current timestamps:")
        stats = os.stat(test_file)
        print(f"Modified: {datetime.datetime.fromtimestamp(stats.st_mtime)}")
        print(f"Accessed: {datetime.datetime.fromtimestamp(stats.st_atime)}")
        print(f"Changed: {datetime.datetime.fromtimestamp(stats.st_ctime)}")
        
        # Modify timestamps
        one_year_ago = datetime.datetime.now() - datetime.timedelta(days=365)
        print(f"\nAttempting to set timestamps to {one_year_ago}")
        
        success = manipulator.update_file_times(
            test_file,
            atime=one_year_ago,
            mtime=one_year_ago
        )
        
        print(f"Timestamp modification {'successful' if success else 'failed'}")
        
        print("\nUpdated timestamps:")
        stats = os.stat(test_file)
        print(f"Modified: {datetime.datetime.fromtimestamp(stats.st_mtime)}")
        print(f"Accessed: {datetime.datetime.fromtimestamp(stats.st_atime)}")
        print(f"Changed: {datetime.datetime.fromtimestamp(stats.st_ctime)} (not directly modifiable)")

if __name__ == "__main__":
    demonstrate_ext4_manipulation()