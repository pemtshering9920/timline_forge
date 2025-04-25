#!/usr/bin/env python3
"""
Timeline Forge - Advanced Metadata Manipulation Utility

A forensic-grade tool for interacting with and modifying low-level system metadata
associated with file and activity timelines across NTFS and EXT4 filesystems.

This modular utility supports manipulation of:
- File timestamps (creation, modification, access)
- Master File Table (MFT) records
- USN Journal entries
- EXT4 inodes and extended attributes
- Transaction logs and journal entries
- Registry LastWrite values
- Windows Prefetch timestamps

IMPORTANT: This tool requires appropriate permissions and should only be used in
authorized testing environments with explicit permission.
"""

import os
import sys
import click
import json
import datetime
import platform
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dateutil import parser

# Import our modules
from metadata_manipulator import (
    MetadataManipulationTool,
    MetadataType,
    FileSystem,
    OperationResult
)

# Optional imports for specific filesystem support
try:
    from ntfs_manipulator import NTFSManipulator
    ntfs_support = True
except ImportError:
    ntfs_support = False

try:
    from ext4_manipulator import EXT4Manipulator
    ext4_support = True
except ImportError:
    ext4_support = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('timeline_forge.log')
    ]
)
logger = logging.getLogger(__name__)

# Check if running with sufficient privileges
def check_privileges() -> bool:
    """Check if the tool is running with sufficient privileges."""
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux
            return os.geteuid() == 0
    except:
        return False

# Main CLI group
@click.group()
@click.version_option(version="1.0.0")
@click.option('--verbose', is_flag=True, help='Enable verbose logging')
def cli(verbose):
    """Timeline Forge - Advanced Metadata Manipulation Utility
    
    A forensic-grade tool for interacting with and modifying low-level system
    metadata associated with file and activity timelines.
    
    This tool requires appropriate permissions and should only be used in
    authorized testing environments with explicit permission.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Check privileges
    is_privileged = check_privileges()
    logger.info(f"Running with elevated privileges: {'Yes' if is_privileged else 'No'}")
    
    if not is_privileged:
        click.echo("WARNING: Running without elevated privileges.")
        click.echo("Some operations may be limited or simulated.")
    
    # Log available modules
    logger.info(f"NTFS support: {'Available' if ntfs_support else 'Not available'}")
    logger.info(f"EXT4 support: {'Available' if ext4_support else 'Not available'}")

# Timeline inspection command
@cli.command('inspect')
@click.argument('target', type=click.Path(exists=True))
@click.option('--type', 'metadata_type', help='Type of metadata to inspect')
@click.option('--json', 'json_output', is_flag=True, help='Output in JSON format')
def inspect_timeline(target, metadata_type, json_output):
    """Inspect timeline metadata for a target file or directory."""
    tool = MetadataManipulationTool()
    result = tool.initialize(target)
    
    if not result.success:
        click.echo(f"Error: {result.message}")
        return
    
    # Get filesystem type
    fs_type = tool.detect_filesystem()
    
    # Create output data
    data = {
        'target': target,
        'filesystem': fs_type
    }
    
    # If specific metadata type requested
    if metadata_type:
        try:
            type_data = tool.get_metadata(metadata_type.upper())
            data['metadata'] = type_data
        except Exception as e:
            click.echo(f"Error getting metadata: {str(e)}")
            return
    else:
        # Get standard timestamps
        data['timestamps'] = {}
        for mtype in ['CREATED', 'MODIFIED', 'ACCESSED']:
            try:
                type_data = tool.get_metadata(mtype)
                data['timestamps'][mtype.lower()] = type_data
            except Exception as e:
                logger.error(f"Error getting {mtype} metadata: {str(e)}")
    
    # Advanced filesystem-specific data if available
    if fs_type == 'NTFS' and ntfs_support:
        data['ntfs_specific'] = _get_ntfs_specific_data(target)
    elif fs_type == 'EXT4' and ext4_support:
        data['ext4_specific'] = _get_ext4_specific_data(target)
    
    # Output
    if json_output:
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        _pretty_print_data(data)

def _get_ntfs_specific_data(target: str) -> Dict[str, Any]:
    """Get NTFS-specific data for a target."""
    data = {}
    
    if not ntfs_support:
        return {'error': 'NTFS support not available'}
    
    # Create NTFS manipulator
    manipulator = NTFSManipulator()
    
    # Try to get MFT record (simulated)
    data['mft_record'] = 'Simulated (requires administrator privileges)'
    
    # Try to get USN journal entries (simulated)
    data['usn_journal'] = 'Simulated (requires administrator privileges)'
    
    return data

def _get_ext4_specific_data(target: str) -> Dict[str, Any]:
    """Get EXT4-specific data for a target."""
    data = {}
    
    if not ext4_support:
        return {'error': 'EXT4 support not available'}
    
    # Create EXT4 manipulator
    manipulator = EXT4Manipulator()
    
    # Try to get extended attributes
    try:
        xattrs = manipulator.get_file_extended_attributes(target)
        data['extended_attributes'] = xattrs
    except:
        data['extended_attributes'] = 'Not available'
    
    # Try to get file flags
    try:
        flags = manipulator.get_file_flags(target)
        data['file_flags'] = flags
    except:
        data['file_flags'] = 'Not available'
    
    # Inode details (simulated)
    data['inode'] = 'Simulated (requires root privileges)'
    
    return data

def _pretty_print_data(data: Dict[str, Any]) -> None:
    """Pretty print data structure."""
    click.echo(f"Target: {data['target']}")
    click.echo(f"Filesystem: {data['filesystem']}")
    click.echo("")
    
    if 'timestamps' in data:
        click.echo("Timestamps:")
        for key, value in data['timestamps'].items():
            click.echo(f"  {key.title()}:")
            for k, v in value.items():
                click.echo(f"    {k}: {v}")
    
    if 'metadata' in data:
        click.echo("\nMetadata:")
        for key, value in data['metadata'].items():
            if isinstance(value, dict):
                click.echo(f"  {key}:")
                for k, v in value.items():
                    click.echo(f"    {k}: {v}")
            else:
                click.echo(f"  {key}: {value}")
    
    if 'ntfs_specific' in data:
        click.echo("\nNTFS-specific information:")
        for key, value in data['ntfs_specific'].items():
            click.echo(f"  {key}: {value}")
    
    if 'ext4_specific' in data:
        click.echo("\nEXT4-specific information:")
        for key, value in data['ext4_specific'].items():
            if isinstance(value, dict):
                click.echo(f"  {key}:")
                for k, v in value.items():
                    click.echo(f"    {k}: {v}")
            else:
                click.echo(f"  {key}: {value}")

# Timeline modification command
@cli.command('modify')
@click.argument('target', type=click.Path(exists=True))
@click.option('--type', 'metadata_type', required=True, help='Type of metadata to modify')
@click.option('--value', required=True, help='New value (timestamp, format: YYYY-MM-DD HH:MM:SS)')
@click.option('--no-backup', is_flag=True, help='Skip creating a backup before modification')
def modify_timeline(target, metadata_type, value, no_backup):
    """Modify timeline metadata for a target file or directory."""
    tool = MetadataManipulationTool()
    result = tool.initialize(target, backup=not no_backup)
    
    if not result.success:
        click.echo(f"Error: {result.message}")
        return
    
    # Try to parse value as timestamp if needed
    if metadata_type.upper() in ['CREATED', 'MODIFIED', 'ACCESSED']:
        try:
            value = parser.parse(value)
            click.echo(f"Parsed timestamp: {value.isoformat()}")
        except:
            click.echo(f"Error: Could not parse timestamp from '{value}'")
            click.echo("Format should be 'YYYY-MM-DD HH:MM:SS'")
            return
    
    # Perform the modification
    result = tool.set_metadata(metadata_type.upper(), value)
    
    if result['success']:
        click.echo(f"Success: {result['message']}")
    else:
        click.echo(f"Error: {result['message']}")

# Reset timeline command
@cli.command('reset')
@click.argument('target', type=click.Path(exists=True))
@click.option('--type', 'metadata_type', required=True, help='Type of metadata to reset')
@click.option('--no-backup', is_flag=True, help='Skip creating a backup before reset')
def reset_timeline(target, metadata_type, no_backup):
    """Reset timeline metadata for a target file or directory."""
    tool = MetadataManipulationTool()
    result = tool.initialize(target, backup=not no_backup)
    
    if not result.success:
        click.echo(f"Error: {result.message}")
        return
    
    # Perform the reset
    result = tool.reset_metadata(metadata_type.upper())
    
    if result['success']:
        click.echo(f"Success: {result['message']}")
    else:
        click.echo(f"Error: {result['message']}")

# Backup management command
@cli.command('restore')
@click.argument('target', type=click.Path(exists=True))
def restore_backup(target):
    """Restore a target from its backup."""
    tool = MetadataManipulationTool()
    result = tool.initialize(target, backup=False)
    
    if not result.success:
        click.echo(f"Error: {result.message}")
        return
    
    # Perform the restoration
    result = tool.restore_from_backup()
    
    if result['success']:
        click.echo(f"Success: {result['message']}")
    else:
        click.echo(f"Error: {result['message']}")

# NTFS-specific commands
if ntfs_support:
    @cli.group('ntfs')
    def ntfs_group():
        """NTFS-specific operations."""
        if not ntfs_support:
            click.echo("Error: NTFS support is not available.")
            sys.exit(1)
    
    @ntfs_group.command('mft')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--record', type=int, help='Specific MFT record number to view')
    def ntfs_mft(target, record):
        """View or manipulate MFT records."""
        device = os.path.abspath(target)
        if os.path.isfile(target):
            # For a file, use its containing device
            device = os.path.dirname(device)
        
        manipulator = NTFSManipulator(device)
        
        if record is not None:
            # View specific record
            result = manipulator.read_mft_record(record)
            if result:
                click.echo(json.dumps(result.to_dict(), indent=2, default=str))
            else:
                click.echo(f"Could not read MFT record {record}")
        else:
            # General info
            click.echo(f"NTFS MFT operations on {device}")
            click.echo(f"Administrator privileges: {'Yes' if manipulator.is_administrator else 'No'}")
            click.echo("\nUse --record option to view a specific MFT record.")
    
    @ntfs_group.command('usn')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--entries', type=int, default=10, help='Number of USN Journal entries to show')
    def ntfs_usn(target, entries):
        """View USN Journal entries."""
        device = os.path.abspath(target)
        if os.path.isfile(target):
            # For a file, use its containing device
            device = os.path.dirname(device)
        
        manipulator = NTFSManipulator(device)
        
        # Query USN Journal
        results = manipulator.query_usn_journal(entries)
        
        if results:
            click.echo(f"Found {len(results)} USN Journal entries:")
            for entry in results:
                click.echo(json.dumps(entry.to_dict(), indent=2, default=str))
                click.echo("-" * 40)
        else:
            click.echo("No USN Journal entries found or access denied.")
    
    @ntfs_group.command('logfile')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--action', type=click.Choice(['info', 'clear']), default='info', 
                help='Action to perform on $LogFile')
    def ntfs_logfile(target, action):
        """View or manipulate the $LogFile journal."""
        device = os.path.abspath(target)
        if os.path.isfile(target):
            # For a file, use its containing device
            device = os.path.dirname(device)
        
        manipulator = NTFSManipulator(device)
        
        if action == 'info':
            click.echo(f"$LogFile operations on {device}")
            click.echo(f"Administrator privileges: {'Yes' if manipulator.is_administrator else 'No'}")
            click.echo("\nNote: Detailed $LogFile analysis would require specialized tools.")
        elif action == 'clear':
            if click.confirm("Are you sure you want to attempt to clear the $LogFile journal? This is dangerous and may corrupt the filesystem."):
                result = manipulator.manipulate_logfile(action='clear')
                if result:
                    click.echo("$LogFile manipulation simulated successfully.")
                else:
                    click.echo("$LogFile manipulation failed or permission denied.")
            else:
                click.echo("Operation cancelled.")

# EXT4-specific commands
if ext4_support:
    @cli.group('ext4')
    def ext4_group():
        """EXT4-specific operations."""
        if not ext4_support:
            click.echo("Error: EXT4 support is not available.")
            sys.exit(1)
    
    @ext4_group.command('inode')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--number', type=int, help='Specific inode number to view')
    def ext4_inode(target, number):
        """View or manipulate EXT4 inodes."""
        device = os.path.abspath(target)
        if os.path.isfile(target):
            # For a file, use its containing device
            device = os.path.dirname(device)
        
        manipulator = EXT4Manipulator(device)
        
        if number is not None:
            # View specific inode
            result = manipulator.read_inode(number)
            if result:
                click.echo(json.dumps(result.to_dict(), indent=2, default=str))
            else:
                click.echo(f"Could not read inode {number}")
        else:
            # General info
            click.echo(f"EXT4 inode operations on {device}")
            click.echo(f"Root privileges: {'Yes' if manipulator.is_root else 'No'}")
            click.echo(f"debugfs available: {'Yes' if manipulator.debugfs_available else 'No'}")
            click.echo(f"e2fsprogs available: {'Yes' if manipulator.e2fsprogs_available else 'No'}")
            click.echo("\nUse --number option to view a specific inode.")
    
    @ext4_group.command('xattr')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--set', 'set_attr', is_flag=True, help='Set an extended attribute')
    @click.option('--remove', 'rem_attr', is_flag=True, help='Remove an extended attribute')
    @click.option('--name', help='Name of the extended attribute')
    @click.option('--value', help='Value for the extended attribute')
    def ext4_xattr(target, set_attr, rem_attr, name, value):
        """View or manipulate extended attributes."""
        manipulator = EXT4Manipulator()
        
        if set_attr:
            if not name or not value:
                click.echo("Error: Both --name and --value are required when setting an attribute.")
                return
            
            result = manipulator.set_file_extended_attribute(target, name, value)
            if result:
                click.echo(f"Successfully set {name}={value}")
            else:
                click.echo(f"Failed to set {name}")
        
        elif rem_attr:
            if not name:
                click.echo("Error: --name is required when removing an attribute.")
                return
            
            result = manipulator.remove_file_extended_attribute(target, name)
            if result:
                click.echo(f"Successfully removed {name}")
            else:
                click.echo(f"Failed to remove {name}")
        
        else:
            # Just view
            attrs = manipulator.get_file_extended_attributes(target)
            if attrs:
                click.echo(f"Extended attributes for {target}:")
                for name, value in attrs.items():
                    click.echo(f"  {name}={value}")
            else:
                click.echo(f"No extended attributes found for {target}")
    
    @ext4_group.command('flags')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--set', 'set_flags', help='Comma-separated list of flags to set')
    @click.option('--clear', is_flag=True, help='Clear all flags')
    def ext4_flags(target, set_flags, clear):
        """View or manipulate file flags."""
        manipulator = EXT4Manipulator()
        
        if set_flags:
            flags = [f.strip().upper() for f in set_flags.split(',')]
            result = manipulator.set_file_flags(target, flags)
            if result:
                click.echo(f"Successfully set flags: {', '.join(flags)}")
            else:
                click.echo("Failed to set flags")
        
        elif clear:
            result = manipulator.clear_file_flags(target)
            if result:
                click.echo("Successfully cleared all flags")
            else:
                click.echo("Failed to clear flags")
        
        else:
            # Just view
            flags = manipulator.get_file_flags(target)
            if flags:
                click.echo(f"Flags for {target}:")
                for flag in flags:
                    click.echo(f"  {flag}")
            else:
                click.echo(f"No flags found for {target} or operation failed")
    
    @ext4_group.command('journal')
    @click.argument('target', type=click.Path(exists=True))
    @click.option('--clear', is_flag=True, help='Clear the journal')
    @click.option('--blocks', type=int, default=10, help='Number of journal blocks to show')
    def ext4_journal(target, clear, blocks):
        """View or manipulate the EXT4 journal."""
        device = os.path.abspath(target)
        if os.path.isfile(target):
            # For a file, use its containing device
            device = os.path.dirname(device)
        
        manipulator = EXT4Manipulator(device)
        
        if clear:
            if click.confirm("Are you sure you want to clear the EXT4 journal? This requires root privileges and may affect filesystem stability."):
                result = manipulator.clear_journal()
                if result:
                    click.echo("Journal clearing simulated successfully.")
                else:
                    click.echo("Journal clearing failed or permission denied.")
            else:
                click.echo("Operation cancelled.")
        else:
            # Query journal
            blocks = manipulator.query_journal(blocks)
            
            if blocks:
                click.echo(f"Found {len(blocks)} journal blocks:")
                for i, block in enumerate(blocks):
                    click.echo(f"Block {i+1}:")
                    click.echo(json.dumps(block.to_dict(), indent=2, default=str))
                    click.echo("-" * 40)
            else:
                click.echo("No journal blocks found or access denied.")

if __name__ == '__main__':
    cli()