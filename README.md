# Timeline Forge

## Advanced Metadata Manipulation Utility

Timeline Forge is basic PoC (Proof Of Concept), forensic-grade utility designed for programmatically interacting with and modifying low-level system metadata associated with file and activity timelines. The tool is modular and supports manipulation of metadata on both NTFS and EXT4 filesystems, providing cross-platform compatibility for security researchers, digital forensics specialists, and red teams.

> **IMPORTANT**: This tool requires administrative/root privileges to perform many operations and should only be used in authorized testing environments or with explicit permission on systems you own. Improper use may result in filesystem corruption or data loss.

## Key Features

* **Cross-Platform Support**: Works with both Windows (NTFS) and Linux (EXT4) filesystems
* **Comprehensive Coverage**: Manipulates metadata across multiple layers including:
  * Basic file timestamps (creation, modification, access)
  * NTFS-specific structures (MFT records, USN Journal, $LogFile)
  * EXT4-specific structures (inodes, extended attributes, journal entries)
  * Registry timestamps (Windows)
  * Prefetch data (Windows)
* **Modular Design**: Core functionality with filesystem-specific extensions
* **Safety Features**: Built-in backup and restore capabilities
* **Command-Line Interface**: Easy to use and integrate into scripts or larger frameworks

## Use Cases

* **Security Research**: Test detection mechanisms for anti-forensic techniques
* **Red Team Operations**: Modify timeline data in authorized penetration testing scenarios
* **Forensic Training**: Demonstrate timeline manipulation techniques in controlled environments
* **Anti-Tamper Testing**: Evaluate the effectiveness of anti-tampering mechanisms
* **Digital Forensics Simulation**: Create realistic forensic challenges for training purposes

## Installation

### Prerequisites

* Python 3.8 or later
* Admin/root privileges for most operations
* For EXT4 support: Linux system with e2fsprogs installed
* For NTFS support: Windows system or Linux with ntfs-3g tools

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/timeline-forge.git
   cd timeline-forge
   ```

2. Install dependencies(N.A):
   ```
   pip install -r requirements.txt
   ```

## Usage

Timeline Forge provides a command-line interface with multiple subcommands for different types of operations.

### Basic Usage

```bash
# Display help
python3 timeline_forge.py --help

# Inspect metadata for a file
python3 timeline_forge.py inspect /path/to/file

# Modify a timestamp
python3 timeline_forge.py modify /path/to/file --type MODIFIED --value "2023-01-15 08:30:00"

# Reset a timestamp to current time
python3 timeline_forge.py reset /path/to/file --type ACCESSED

# Restore from backup
python3 timeline_forge.py restore /path/to/file
```

### NTFS-Specific Operations

```bash
# View MFT record
python3 timeline_forge.py ntfs mft /path/to/volume --record 5

# Query USN Journal entries
python3 timeline_forge.py ntfs usn /path/to/volume --entries 20

# View $LogFile information
python3 timeline_forge.py ntfs logfile /path/to/volume
```

### EXT4-Specific Operations

```bash
# View inode details
python3 timeline_forge.py ext4 inode /path/to/file --number 12345

# View extended attributes
python3 timeline_forge.py ext4 xattr /path/to/file

# Set an extended attribute
python3 timeline_forge.py ext4 xattr /path/to/file --set --name user.example --value test

# View file flags
python3 timeline_forge.py ext4 flags /path/to/file

# Set file flags
python3 timeline_forge.py ext4 flags /path/to/file --set IMMUTABLE,NO_ATIME

# View journal entries
python3 timeline_forge.py ext4 journal /path/to/volume --blocks 5
```

## Module Components

Timeline Forge is organized into several modular components:

* **metadata_manipulator.py**: Core classes and platform-independent functions
* **ntfs_manipulator.py**: NTFS-specific implementation for Windows systems
* **ext4_manipulator.py**: EXT4-specific implementation for Linux systems
* **timeline_forge.py**: Command-line interface and integration layer

## Technical Details

### NTFS Metadata Manipulation

The tool provides capabilities to interact with:

* **Master File Table (MFT)**: Core database that tracks all files on an NTFS volume
* **$STANDARD_INFORMATION Attribute**: Contains file timestamps and other metadata
* **USN Journal**: Change journal that records changes to files and directories
* **$LogFile**: Transaction log used for recovery after system crashes

### EXT4 Metadata Manipulation

On EXT4 filesystems, the tool can work with:

* **Inodes**: Data structures containing file metadata
* **Extended Attributes**: Name-value pairs associated with files
* **File Flags**: Special attributes like immutability or append-only
* **Journal**: Transaction log for filesystem changes

## Safety Considerations

* **Backups**: The tool creates backups before modifying critical structures
* **Permissions**: Administrative/root privileges are required for most operations
* **Simulation Mode**: Many operations provide a simulation option for safer testing
* **Informed Consent**: Clear warnings are provided for potentially dangerous operations

## Limitations

* Some operations are simulated rather than fully implemented when they would be too dangerous
* Registry manipulation requires Windows-specific APIs and may not work in all environments
* Direct journal manipulation is limited to avoid filesystem corruption
* The tool should not be used on production systems or without proper authorization

## Legal Disclaimer

This tool is provided for research and authorized testing purposes only. Misuse of this tool may violate laws and regulations regarding computer fraud and abuse. Always obtain proper authorization before using on any system. The authors are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

* This tool builds upon research in digital forensics and anti-forensics techniques
* Special thanks to the digital forensics community for documenting filesystem internals
* Inspired by forensic tools like The Sleuth Kit, Autopsy, and FTK Imager
