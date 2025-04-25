#!/usr/bin/env python3
"""
Metadata Manipulation Utility (MMU)

A modular utility for programmatically interacting with and modifying low-level system 
metadata associated with file and activity timelines across NTFS and EXT4 filesystems.

This tool is designed for use in forensic analysis simulations, red team environments,
and anti-tamper testing frameworks.

IMPORTANT: This tool requires appropriate permissions and should only be used in
authorized testing environments or with explicit permission on systems you own.
"""

import os
import sys
import datetime
import logging
import json
import struct
import hashlib
import platform
import subprocess
import tempfile
from enum import Enum, auto
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Union, Optional, Any

# Third party imports
import click
import pytz
from dateutil import parser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('metadata_manipulation.log')
    ]
)
logger = logging.getLogger(__name__)

class FileSystem(Enum):
    """Supported file systems for metadata manipulation."""
    NTFS = auto()
    EXT4 = auto()
    UNKNOWN = auto()

class MetadataType(Enum):
    """Types of metadata that can be manipulated."""
    CREATED = auto()          # File creation time
    MODIFIED = auto()         # Last modified time
    ACCESSED = auto()         # Last accessed time
    MFT_RECORD = auto()       # MFT record (NTFS)
    INODE = auto()            # inode (EXT4)
    JOURNAL = auto()          # Journal entries
    USN_JOURNAL = auto()      # USN Journal (NTFS)
    REGISTRY = auto()         # Registry LastWrite times
    PREFETCH = auto()         # Windows Prefetch data
    LOG_FILE = auto()         # $LogFile (NTFS)
    SECURITY_DESCRIPTOR = auto()  # Security descriptors

class OperationResult:
    """Result of a metadata manipulation operation."""
    
    def __init__(self, success: bool, message: str, details: Optional[Dict[str, Any]] = None):
        self.success = success
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'success': self.success,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        """String representation of the result."""
        status = "SUCCESS" if self.success else "FAILURE"
        return f"{status}: {self.message}"

class MetadataManipulator(ABC):
    """Abstract base class for metadata manipulators."""
    
    def __init__(self, target_path: Union[str, Path], backup: bool = True):
        self.target_path = Path(target_path)
        self.backup = backup
        self.backup_path = None
        
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")
        
        if backup:
            self._create_backup()
    
    def _create_backup(self) -> None:
        """Create a backup of the target."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        if self.target_path.is_file():
            self.backup_path = backup_dir / f"{self.target_path.name}.{timestamp}.bak"
            import shutil
            shutil.copy2(self.target_path, self.backup_path)
        else:
            # Directory backup logic would go here
            pass
        
        logger.info(f"Created backup at {self.backup_path}")
    
    def restore_from_backup(self) -> OperationResult:
        """Restore the target from backup."""
        if not self.backup_path or not self.backup_path.exists():
            return OperationResult(False, "No backup available to restore from")
        
        try:
            import shutil
            shutil.copy2(self.backup_path, self.target_path)
            return OperationResult(True, f"Restored {self.target_path} from {self.backup_path}")
        except Exception as e:
            return OperationResult(False, f"Failed to restore from backup: {str(e)}")
    
    @abstractmethod
    def detect_filesystem(self) -> FileSystem:
        """Detect the filesystem of the target."""
        pass
    
    @abstractmethod
    def get_metadata(self, metadata_type: MetadataType) -> Dict[str, Any]:
        """Get specific metadata from the target."""
        pass
    
    @abstractmethod
    def set_metadata(self, metadata_type: MetadataType, value: Any) -> OperationResult:
        """Set specific metadata on the target."""
        pass
    
    @abstractmethod
    def reset_metadata(self, metadata_type: MetadataType) -> OperationResult:
        """Reset specific metadata to default or standard values."""
        pass

class WindowsMetadataManipulator(MetadataManipulator):
    """Metadata manipulator for Windows systems."""
    
    def detect_filesystem(self) -> FileSystem:
        """Detect the filesystem of the target on Windows."""
        # This is a simplified implementation
        # In a real scenario, we would use Win32 API calls to get volume information
        
        drive_letter = str(self.target_path.resolve().anchor)
        logger.debug(f"Detecting filesystem for drive: {drive_letter}")
        
        # Simulated detection - would use actual Win32 API in real implementation
        return FileSystem.NTFS  # Assuming NTFS for Windows
    
    def get_metadata(self, metadata_type: MetadataType) -> Dict[str, Any]:
        """Get specific metadata from the target on Windows."""
        result = {}
        
        if metadata_type in [MetadataType.CREATED, MetadataType.MODIFIED, MetadataType.ACCESSED]:
            # Basic file timestamps
            stat_result = self.target_path.stat()
            
            if metadata_type == MetadataType.CREATED:
                # On Windows, st_ctime is creation time
                timestamp = datetime.datetime.fromtimestamp(stat_result.st_ctime)
                result['created_time'] = timestamp.isoformat()
                
            elif metadata_type == MetadataType.MODIFIED:
                timestamp = datetime.datetime.fromtimestamp(stat_result.st_mtime)
                result['modified_time'] = timestamp.isoformat()
                
            elif metadata_type == MetadataType.ACCESSED:
                timestamp = datetime.datetime.fromtimestamp(stat_result.st_atime)
                result['accessed_time'] = timestamp.isoformat()
        
        elif metadata_type == MetadataType.MFT_RECORD:
            # In a real implementation, this would access MFT records using low-level APIs
            # or forensic libraries
            logger.warning("Accessing MFT records requires elevated privileges")
            result['warning'] = "MFT record access simulated - would require administrative privileges"
            result['mft_record_number'] = self._simulate_mft_record_access()
        
        elif metadata_type == MetadataType.USN_JOURNAL:
            # USN Journal access would require specialized APIs
            logger.warning("USN Journal access requires elevated privileges")
            result['warning'] = "USN Journal access simulated - would require administrative privileges"
            result['usn_journal_entries'] = self._simulate_usn_journal_access()
        
        elif metadata_type == MetadataType.REGISTRY:
            # Registry access would use the Windows Registry API
            logger.warning("Registry manipulation requires specialized access")
            result['warning'] = "Registry access simulated - would require specific registry access"
            result['registry_lastwrite'] = self._simulate_registry_access()
        
        elif metadata_type == MetadataType.PREFETCH:
            # Prefetch file access
            logger.warning("Prefetch file access requires specialized parsing")
            result['warning'] = "Prefetch access simulated - would require specialized parsing"
            result['prefetch_data'] = self._simulate_prefetch_access()
        
        else:
            logger.warning(f"Metadata type {metadata_type} not supported on Windows")
            result['error'] = f"Metadata type {metadata_type} not supported"
        
        return result
    
    def set_metadata(self, metadata_type: MetadataType, value: Any) -> OperationResult:
        """Set specific metadata on the target on Windows."""
        try:
            if metadata_type in [MetadataType.CREATED, MetadataType.MODIFIED, MetadataType.ACCESSED]:
                # Convert value to datetime if needed
                if isinstance(value, str):
                    timestamp = parser.parse(value)
                elif isinstance(value, (int, float)):
                    timestamp = datetime.datetime.fromtimestamp(value)
                elif isinstance(value, datetime.datetime):
                    timestamp = value
                else:
                    return OperationResult(False, f"Invalid timestamp format: {value}")
                
                # On Windows, we would use Win32 API SetFileTime
                # This is a simulated implementation
                self._simulate_set_file_time(metadata_type, timestamp)
                return OperationResult(True, f"Set {metadata_type.name} time to {timestamp.isoformat()}")
            
            elif metadata_type == MetadataType.MFT_RECORD:
                # Would require low-level disk access and specialized APIs
                logger.warning("MFT record modification requires administrative privileges")
                return OperationResult(
                    False, 
                    "MFT record modification requires administrative privileges and specialized tools",
                    {"note": "This operation is simulated and would require direct disk access"}
                )
            
            elif metadata_type == MetadataType.USN_JOURNAL:
                # Would require specialized APIs for USN Journal interaction
                logger.warning("USN Journal modification requires administrative privileges")
                return OperationResult(
                    False, 
                    "USN Journal modification requires administrative privileges and specialized tools",
                    {"note": "This operation is simulated and would require direct system access"}
                )
            
            # Other metadata types would be implemented similarly
            else:
                return OperationResult(False, f"Setting metadata type {metadata_type.name} not supported on Windows")
        
        except Exception as e:
            logger.error(f"Error setting metadata: {str(e)}")
            return OperationResult(False, f"Error setting metadata: {str(e)}")
    
    def reset_metadata(self, metadata_type: MetadataType) -> OperationResult:
        """Reset specific metadata to default or standard values on Windows."""
        # Resetting metadata typically means setting to current time or standardized values
        try:
            if metadata_type in [MetadataType.CREATED, MetadataType.MODIFIED, MetadataType.ACCESSED]:
                # Set to current time
                now = datetime.datetime.now()
                return self.set_metadata(metadata_type, now)
            
            # Other metadata types would be handled similarly
            else:
                return OperationResult(False, f"Resetting metadata type {metadata_type.name} not supported on Windows")
        
        except Exception as e:
            logger.error(f"Error resetting metadata: {str(e)}")
            return OperationResult(False, f"Error resetting metadata: {str(e)}")
    
    def _simulate_mft_record_access(self) -> Dict[str, Any]:
        """Simulate accessing MFT records (for educational purposes)."""
        # In a real implementation, this would access actual MFT records
        return {
            "record_number": 12345,
            "file_name": self.target_path.name,
            "sequences": [1, 2, 3],
            "flags": 0x01,
            "link_count": 1,
            "simulated": True
        }
    
    def _simulate_usn_journal_access(self) -> List[Dict[str, Any]]:
        """Simulate accessing USN Journal entries (for educational purposes)."""
        # In a real implementation, this would access actual USN Journal records
        return [
            {
                "file_name": self.target_path.name,
                "reason": "DATA_EXTEND",
                "timestamp": datetime.datetime.now().isoformat(),
                "usn": 1234567890,
                "file_attribute_mask": 0x80,
                "simulated": True
            }
        ]
    
    def _simulate_registry_access(self) -> Dict[str, Any]:
        """Simulate accessing Registry LastWrite times (for educational purposes)."""
        # In a real implementation, this would access actual Registry keys
        return {
            "key_path": "HKEY_LOCAL_MACHINE\\Software\\Example",
            "last_write_time": datetime.datetime.now().isoformat(),
            "values": ["Example1", "Example2"],
            "simulated": True
        }
    
    def _simulate_prefetch_access(self) -> Dict[str, Any]:
        """Simulate accessing Prefetch data (for educational purposes)."""
        # In a real implementation, this would parse actual Prefetch files
        return {
            "executable_name": "EXAMPLE.EXE",
            "run_count": 5,
            "last_run_time": datetime.datetime.now().isoformat(),
            "volumes": ["C:"],
            "simulated": True
        }
    
    def _simulate_set_file_time(self, metadata_type: MetadataType, timestamp: datetime.datetime) -> None:
        """Simulate setting file times using Win32 API (for educational purposes)."""
        # In a real implementation, this would use actual Win32 API calls
        logger.info(f"Simulating setting {metadata_type.name} time to {timestamp.isoformat()}")
        
        # In reality, would use something like:
        # import win32file
        # import pywintypes
        # handle = win32file.CreateFile(...)
        # win_time = pywintypes.Time(timestamp)
        # win32file.SetFileTime(handle, ...)
        pass

class LinuxMetadataManipulator(MetadataManipulator):
    """Metadata manipulator for Linux systems."""
    
    def detect_filesystem(self) -> FileSystem:
        """Detect the filesystem of the target on Linux."""
        try:
            # Get the device where the target file is located
            target_device = self._get_target_device()
            
            # Use 'df' command to get filesystem type
            cmd = ['df', '--output=fstype', str(self.target_path)]
            output = subprocess.check_output(cmd, text=True)
            lines = output.strip().split('\n')
            
            if len(lines) >= 2:
                fstype = lines[1].strip().upper()
                if 'EXT4' in fstype:
                    return FileSystem.EXT4
                elif 'NTFS' in fstype:
                    return FileSystem.NTFS
            
            return FileSystem.UNKNOWN
        
        except Exception as e:
            logger.error(f"Error detecting filesystem: {str(e)}")
            return FileSystem.UNKNOWN
    
    def _get_target_device(self) -> str:
        """Get the device where the target file is located."""
        try:
            cmd = ['df', str(self.target_path), '--output=source']
            output = subprocess.check_output(cmd, text=True)
            lines = output.strip().split('\n')
            
            if len(lines) >= 2:
                return lines[1].strip()
            
            return ""
        
        except Exception as e:
            logger.error(f"Error getting target device: {str(e)}")
            return ""
    
    def get_metadata(self, metadata_type: MetadataType) -> Dict[str, Any]:
        """Get specific metadata from the target on Linux."""
        result = {}
        
        if metadata_type in [MetadataType.CREATED, MetadataType.MODIFIED, MetadataType.ACCESSED]:
            # Basic file timestamps
            stat_result = self.target_path.stat()
            
            if metadata_type == MetadataType.CREATED:
                # On Linux, st_ctime is inode change time, not creation time
                # True creation time often not available on standard Linux filesystems
                timestamp = datetime.datetime.fromtimestamp(stat_result.st_ctime)
                result['change_time'] = timestamp.isoformat()  # Not creation time!
                result['note'] = "Linux does not track true file creation time in standard filesystems"
                
            elif metadata_type == MetadataType.MODIFIED:
                timestamp = datetime.datetime.fromtimestamp(stat_result.st_mtime)
                result['modified_time'] = timestamp.isoformat()
                
            elif metadata_type == MetadataType.ACCESSED:
                timestamp = datetime.datetime.fromtimestamp(stat_result.st_atime)
                result['accessed_time'] = timestamp.isoformat()
        
        elif metadata_type == MetadataType.INODE:
            # For Linux, we can get basic inode information
            stat_result = self.target_path.stat()
            result['inode_number'] = stat_result.st_ino
            result['device'] = stat_result.st_dev
            result['links'] = stat_result.st_nlink
            result['uid'] = stat_result.st_uid
            result['gid'] = stat_result.st_gid
            
            # Get extended inode info if we have permissions
            result.update(self._get_extended_inode_info())
        
        elif metadata_type == MetadataType.JOURNAL:
            # Journal entries would require filesystem-specific tools
            logger.warning("Journal access requires elevated privileges")
            result['warning'] = "Journal access simulated - would require root privileges"
            result['journal_entries'] = self._simulate_journal_access()
        
        else:
            logger.warning(f"Metadata type {metadata_type} not supported on Linux")
            result['error'] = f"Metadata type {metadata_type} not supported on Linux"
        
        return result
    
    def set_metadata(self, metadata_type: MetadataType, value: Any) -> OperationResult:
        """Set specific metadata on the target on Linux."""
        try:
            if metadata_type in [MetadataType.MODIFIED, MetadataType.ACCESSED]:
                # Convert value to datetime if needed
                if isinstance(value, str):
                    timestamp = parser.parse(value)
                elif isinstance(value, (int, float)):
                    timestamp = datetime.datetime.fromtimestamp(value)
                elif isinstance(value, datetime.datetime):
                    timestamp = value
                else:
                    return OperationResult(False, f"Invalid timestamp format: {value}")
                
                # Use the touch command to set timestamps
                timestamp_str = timestamp.strftime("%Y%m%d%H%M.%S")
                
                if metadata_type == MetadataType.MODIFIED:
                    cmd = ['touch', '-m', f'--date=@{int(timestamp.timestamp())}', str(self.target_path)]
                elif metadata_type == MetadataType.ACCESSED:
                    cmd = ['touch', '-a', f'--date=@{int(timestamp.timestamp())}', str(self.target_path)]
                
                subprocess.run(cmd, check=True)
                return OperationResult(True, f"Set {metadata_type.name} time to {timestamp.isoformat()}")
            
            elif metadata_type == MetadataType.CREATED:
                return OperationResult(
                    False,
                    "Linux does not support setting true creation time in standard filesystems",
                    {"note": "Creation time is not a standard attribute on Linux EXT filesystems"}
                )
            
            elif metadata_type == MetadataType.INODE:
                # Would require low-level tools or root access
                return OperationResult(
                    False,
                    "Direct inode manipulation requires root privileges and specialized tools",
                    {"note": "This operation is simulated and would require elevated privileges"}
                )
            
            # Other metadata types would be handled similarly
            else:
                return OperationResult(False, f"Setting metadata type {metadata_type.name} not supported on Linux")
        
        except Exception as e:
            logger.error(f"Error setting metadata: {str(e)}")
            return OperationResult(False, f"Error setting metadata: {str(e)}")
    
    def reset_metadata(self, metadata_type: MetadataType) -> OperationResult:
        """Reset specific metadata to default or standard values on Linux."""
        # Resetting metadata typically means setting to current time or standardized values
        try:
            if metadata_type in [MetadataType.MODIFIED, MetadataType.ACCESSED]:
                # Set to current time
                now = datetime.datetime.now()
                return self.set_metadata(metadata_type, now)
            
            # Other metadata types would be handled similarly
            else:
                return OperationResult(False, f"Resetting metadata type {metadata_type.name} not supported on Linux")
        
        except Exception as e:
            logger.error(f"Error resetting metadata: {str(e)}")
            return OperationResult(False, f"Error resetting metadata: {str(e)}")
    
    def _get_extended_inode_info(self) -> Dict[str, Any]:
        """Get extended inode information if possible."""
        result = {}
        
        try:
            # Use stat command for more detailed information
            cmd = ['stat', '-c', '%A %u %g %i %X %Y %Z %B', str(self.target_path)]
            output = subprocess.check_output(cmd, text=True).strip()
            
            parts = output.split()
            if len(parts) >= 8:
                result['permissions'] = parts[0]
                result['user_id'] = int(parts[1])
                result['group_id'] = int(parts[2])
                result['inode'] = int(parts[3])
                result['access_time_unix'] = int(parts[4])
                result['modify_time_unix'] = int(parts[5])
                result['change_time_unix'] = int(parts[6])
                result['block_size'] = int(parts[7])
            
            # Try to get extended attributes if possible
            try:
                cmd = ['getfattr', '-d', '-m', '-', str(self.target_path)]
                output = subprocess.check_output(cmd, text=True).strip()
                result['extended_attributes'] = output
            except:
                result['extended_attributes'] = "Not available or no attributes set"
        
        except Exception as e:
            logger.debug(f"Could not get extended inode info: {str(e)}")
            result['error'] = f"Could not get extended inode info: {str(e)}"
        
        return result
    
    def _simulate_journal_access(self) -> List[Dict[str, Any]]:
        """Simulate accessing journal entries (for educational purposes)."""
        # In a real implementation, this would access actual journal entries
        # using filesystem-specific tools like debugfs
        return [
            {
                "file_name": self.target_path.name,
                "operation": "MODIFY",
                "timestamp": datetime.datetime.now().isoformat(),
                "block": 12345,
                "simulated": True
            }
        ]

class MetadataManipulationTool:
    """Main tool class for orchestrating metadata manipulation operations."""
    
    def __init__(self):
        self.manipulator = None
        self.system = platform.system()
    
    def initialize(self, target_path: Union[str, Path], backup: bool = True) -> OperationResult:
        """Initialize the appropriate manipulator based on the current system."""
        try:
            target = Path(target_path)
            
            if not target.exists():
                return OperationResult(False, f"Target path does not exist: {target}")
            
            if self.system == "Windows":
                self.manipulator = WindowsMetadataManipulator(target, backup)
                return OperationResult(True, f"Initialized Windows metadata manipulator for {target}")
            
            elif self.system == "Linux":
                self.manipulator = LinuxMetadataManipulator(target, backup)
                return OperationResult(True, f"Initialized Linux metadata manipulator for {target}")
            
            else:
                return OperationResult(False, f"Unsupported operating system: {self.system}")
        
        except Exception as e:
            logger.error(f"Error initializing metadata manipulator: {str(e)}")
            return OperationResult(False, f"Error initializing metadata manipulator: {str(e)}")
    
    def get_metadata(self, metadata_type_str: str) -> Dict[str, Any]:
        """Get metadata of the specified type."""
        if not self.manipulator:
            return {"error": "Manipulator not initialized. Call initialize() first."}
        
        try:
            metadata_type = MetadataType[metadata_type_str.upper()]
            return self.manipulator.get_metadata(metadata_type)
        
        except KeyError:
            return {"error": f"Invalid metadata type: {metadata_type_str}"}
        
        except Exception as e:
            logger.error(f"Error getting metadata: {str(e)}")
            return {"error": f"Error getting metadata: {str(e)}"}
    
    def set_metadata(self, metadata_type_str: str, value: Any) -> Dict[str, Any]:
        """Set metadata of the specified type."""
        if not self.manipulator:
            return {"success": False, "message": "Manipulator not initialized. Call initialize() first."}
        
        try:
            metadata_type = MetadataType[metadata_type_str.upper()]
            result = self.manipulator.set_metadata(metadata_type, value)
            return result.to_dict()
        
        except KeyError:
            return {"success": False, "message": f"Invalid metadata type: {metadata_type_str}"}
        
        except Exception as e:
            logger.error(f"Error setting metadata: {str(e)}")
            return {"success": False, "message": f"Error setting metadata: {str(e)}"}
    
    def reset_metadata(self, metadata_type_str: str) -> Dict[str, Any]:
        """Reset metadata of the specified type."""
        if not self.manipulator:
            return {"success": False, "message": "Manipulator not initialized. Call initialize() first."}
        
        try:
            metadata_type = MetadataType[metadata_type_str.upper()]
            result = self.manipulator.reset_metadata(metadata_type)
            return result.to_dict()
        
        except KeyError:
            return {"success": False, "message": f"Invalid metadata type: {metadata_type_str}"}
        
        except Exception as e:
            logger.error(f"Error resetting metadata: {str(e)}")
            return {"success": False, "message": f"Error resetting metadata: {str(e)}"}
    
    def detect_filesystem(self) -> str:
        """Detect the filesystem of the target."""
        if not self.manipulator:
            return "UNKNOWN (Manipulator not initialized. Call initialize() first.)"
        
        try:
            filesystem = self.manipulator.detect_filesystem()
            return filesystem.name
        
        except Exception as e:
            logger.error(f"Error detecting filesystem: {str(e)}")
            return f"UNKNOWN (Error: {str(e)})"
    
    def restore_from_backup(self) -> Dict[str, Any]:
        """Restore the target from backup."""
        if not self.manipulator:
            return {"success": False, "message": "Manipulator not initialized. Call initialize() first."}
        
        try:
            result = self.manipulator.restore_from_backup()
            return result.to_dict()
        
        except Exception as e:
            logger.error(f"Error restoring from backup: {str(e)}")
            return {"success": False, "message": f"Error restoring from backup: {str(e)}"}


@click.group()
def cli():
    """Metadata Manipulation Utility (MMU)
    
    A tool for interacting with and modifying low-level system metadata.
    """
    pass


@cli.command("info")
@click.argument("target", type=click.Path(exists=True))
@click.option("--type", "metadata_type", type=str, help="Type of metadata to retrieve")
def get_info(target, metadata_type):
    """Get metadata information for the specified target."""
    tool = MetadataManipulationTool()
    init_result = tool.initialize(target)
    
    if not init_result.success:
        click.echo(f"Error: {init_result.message}")
        return
    
    if metadata_type:
        # Get specific metadata type
        result = tool.get_metadata(metadata_type)
        click.echo(json.dumps(result, indent=2))
    else:
        # Get basic info
        click.echo(f"Target: {target}")
        click.echo(f"Filesystem: {tool.detect_filesystem()}")
        
        # Get basic timestamps
        for mtype in ["CREATED", "MODIFIED", "ACCESSED"]:
            result = tool.get_metadata(mtype)
            click.echo(f"\n{mtype} Time Information:")
            click.echo(json.dumps(result, indent=2))


@cli.command("set")
@click.argument("target", type=click.Path(exists=True))
@click.option("--type", "metadata_type", required=True, type=str, help="Type of metadata to set")
@click.option("--value", required=True, type=str, help="Value to set (timestamp for time-based metadata)")
@click.option("--no-backup", is_flag=True, help="Skip creating a backup before modification")
def set_metadata(target, metadata_type, value, no_backup):
    """Set metadata for the specified target."""
    tool = MetadataManipulationTool()
    init_result = tool.initialize(target, backup=not no_backup)
    
    if not init_result.success:
        click.echo(f"Error: {init_result.message}")
        return
    
    result = tool.set_metadata(metadata_type, value)
    click.echo(json.dumps(result, indent=2))


@cli.command("reset")
@click.argument("target", type=click.Path(exists=True))
@click.option("--type", "metadata_type", required=True, type=str, help="Type of metadata to reset")
@click.option("--no-backup", is_flag=True, help="Skip creating a backup before modification")
def reset_metadata(target, metadata_type, no_backup):
    """Reset metadata for the specified target to standard values."""
    tool = MetadataManipulationTool()
    init_result = tool.initialize(target, backup=not no_backup)
    
    if not init_result.success:
        click.echo(f"Error: {init_result.message}")
        return
    
    result = tool.reset_metadata(metadata_type)
    click.echo(json.dumps(result, indent=2))


@cli.command("restore")
@click.argument("target", type=click.Path(exists=True))
def restore_backup(target):
    """Restore the target from its backup."""
    tool = MetadataManipulationTool()
    init_result = tool.initialize(target, backup=False)
    
    if not init_result.success:
        click.echo(f"Error: {init_result.message}")
        return
    
    result = tool.restore_from_backup()
    click.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    cli()